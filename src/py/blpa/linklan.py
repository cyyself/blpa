"""Linksfield / Linklan "BLE-eSIM" — LPAd protobuf over a PSK secured channel.

Verified on hardware (identifiers withheld).  Protocol notes: protocol/linklan.md.

    BLE:      service 6e400001-…, write 6e400002-…, notify 6e400003-…, 2-byte
              big-endian length prefix, chunks of min(512, MTU-3)
    envelope: EuiccDeviceReq { cmd = 1 (0 device, 2 scard, 3 security), request = 2 }
    security: PSK handshake (HMAC-SHA256) then AES-CCM with a 4-byte tag
    eUICC:    APDUs through the SCARD bridge on logical channel 4
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
from typing import List, Optional

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from . import pb, tlv
from .base import BlpaError, Card, CardInfo, Profile

log = logging.getLogger("blpa.linklan")

SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
NAME_PREFIX = "BLE-eSIM"
APP_CHUNK = 512

CMD_DEVICE, CMD_EUICC, CMD_SCARD, CMD_SECURITY = 0, 1, 2, 3
TYPE_AUTH, TYPE_UPDATE = 0, 1
MAX_BLOCK = 240


def psk_from_password(password: str) -> bytes:
    """r4.a(): PSK = HMAC_SHA256(password, "SecurePbChannel")."""
    return hmac.new(password.encode(), b"SecurePbChannel", hashlib.sha256).digest()


def psk_from_eid_suffix(eid: str) -> bytes:
    """The vendor default: the password is the last six digits of the EID."""
    return psk_from_password(eid[-6:])


DEFAULT_PSK = psk_from_password("Linksfield@Esim#2025")


def _hmac(key: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def zz(v: int) -> int:
    return (v << 1) if v >= 0 else ((-v) << 1) - 1


def unzz(v: int) -> int:
    return (v >> 1) ^ -(v & 1)


class LinklanCard(Card):
    kind = "linklan"

    def __init__(self, address: Optional[str] = None, name: Optional[str] = None,
                 psk: Optional[bytes] = None, password: Optional[str] = None,
                 chunk: int = APP_CHUNK, timeout: float = 60.0):
        self.address = address
        self.name_filter = (name or "").lower()
        self.psk = psk or (psk_from_password(password) if password else None) or DEFAULT_PSK
        self.chunk = chunk
        self.timeout = timeout
        self.client: Optional[BleakClient] = None
        self.name = ""
        self.channel = 4
        self._key: Optional[bytes] = None
        self._nonce: bytes = b""
        self._aad: bytes = b""
        self._counter = 0
        self._buf = bytearray()
        self._expect = 0
        self._rsp: Optional[bytes] = None
        self._event = asyncio.Event()
        self._lock = asyncio.Lock()

    # -- link ----------------------------------------------------------- #
    async def _find(self):
        if self.address:
            target = self.address.upper()
            for d in await BleakScanner.discover(timeout=20):
                if d.address.upper() == target:
                    return d
            raise BlpaError(f"device {self.address} not found")
        want = self.name_filter or NAME_PREFIX.lower()
        for _ in range(3):
            for d in await BleakScanner.discover(timeout=8):
                if want in (d.name or "").lower():
                    return d
        raise BlpaError(f"no Linklan card found (name contains {want!r})")

    def _on_notify(self, _char, data: bytearray) -> None:
        data = bytes(data)
        if not self._buf:
            self._expect = int.from_bytes(data[:2], "big")
        self._buf.extend(data)
        if self._expect and len(self._buf) >= self._expect + 2:
            self._rsp = bytes(self._buf[2:2 + self._expect])
            self._event.set()

    async def _send(self, payload: bytes) -> bytes:
        if not self.client:
            raise BlpaError("not connected")
        async with self._lock:
            self._buf.clear(); self._expect = 0; self._rsp = None; self._event.clear()
            frame = len(payload).to_bytes(2, "big") + payload
            mtu = getattr(self.client, "mtu_size", 23) or 23
            size = min(self.chunk, max(20, mtu - 3))
            for off in range(0, len(frame), size):
                await self.client.write_gatt_char(WRITE, frame[off:off + size], response=True)
            try:
                await asyncio.wait_for(self._event.wait(), self.timeout)
            except asyncio.TimeoutError as exc:
                raise BlpaError("Linklan: no reply") from exc
            return self._rsp or b""

    # -- security -------------------------------------------------------- #
    @staticmethod
    def _frame(cmd: int, payload: bytes = b"") -> bytes:
        return pb.enc_int(1, cmd, always=True) + pb.enc_bytes(2, payload)

    async def _classify(self, rsp: bytes):
        try:
            msg = pb.decode(rsp)
        except pb.DecodeError:
            return "plain", rsp
        enc = pb.first(msg, 2)
        sec = pb.first(msg, 3)          # SecurityData.sec
        dsec = pb.first(msg, 5)         # DeviceRsp.security / SecurityData.error
        if isinstance(enc, bytes) and enc:
            return "enc", enc
        if isinstance(sec, bytes) and sec:
            return "protocol", sec
        if isinstance(dsec, bytes) and dsec:
            return "protocol", dsec
        if isinstance(dsec, int):
            return "error", dsec
        return "plain", rsp

    async def _request(self, cmd: int, payload: bytes = b"") -> bytes:
        inner = self._frame(cmd, payload)
        if self._key is None:
            rsp = await self._send(inner)
            kind, value = await self._classify(rsp)
            if kind == "protocol":
                await self._authenticate(value)
                return await self._request(cmd, payload)
            if kind == "error" and value == -256:
                await self._authenticate(None)
                return await self._request(cmd, payload)
            raise BlpaError(f"Linklan: security required ({kind} {value!r})")
        self._counter += 1
        nonce = bytearray(self._nonce)
        n = (int.from_bytes(nonce[8:12], "big") + self._counter) & 0xFFFFFFFF
        nonce[8:12] = n.to_bytes(4, "big")
        ct = AESCCM(self._key, tag_length=4).encrypt(bytes(nonce), inner, self._aad)
        secdata = pb.enc_int(1, self._counter, always=True) + pb.enc_bytes(2, ct)
        rsp = await self._send(self._frame(CMD_SECURITY, secdata))
        kind, value = await self._classify(rsp)
        if kind == "enc":
            plain = AESCCM(self._key, tag_length=4).decrypt(
                bytes(nonce), value, self._aad)
            return plain
        if kind == "protocol":
            self._key = None
            await self._authenticate(value)
            return await self._request(cmd, payload)
        if kind == "error":
            raise BlpaError(f"Linklan: security error {value}")
        return value

    async def _authenticate(self, proto: Optional[bytes]) -> None:
        if proto is None:
            rsp = await self._send(self._frame(CMD_DEVICE, pb.enc_int(1, 1, always=True)))
            kind, value = await self._classify(rsp)
            if kind != "protocol":
                raise BlpaError("Linklan: no challenge")
            proto = value
        auth = pb.first(pb.decode(proto), 2)
        dev_random = pb.first(pb.decode(auth), 1) if auth else None
        if not dev_random:
            raise BlpaError("Linklan: challenge has no random")
        cli_random = os.urandom(16)
        mac = _hmac(self.psk, b"SecurePbChannel", dev_random, cli_random)
        proof = _hmac(mac[:16], cli_random, bytes(32))
        auth_msg = pb.enc_msg(2, pb.enc_bytes(1, cli_random) + pb.enc_bytes(2, proof))
        sec = pb.enc_int(1, TYPE_AUTH) + auth_msg
        for ident in (0, 1, 2, 3, 4, 5):
            data = pb.enc_int(1, ident, always=True) + pb.enc_msg(3, sec)
            rsp = await self._send(self._frame(CMD_SECURITY, data))
            kind, value = await self._classify(rsp)
            if kind == "protocol":
                cfg = pb.first(pb.decode(value), 3)
                if not cfg:
                    continue
                c = pb.decode(cfg)
                self._key = mac[16:32]
                self._nonce = pb.first(c, 1) or b""
                self._aad = pb.first(c, 2) or b""
                self._counter = 0
                log.info("Linklan: secure channel established (id=%d)", ident)
                return
        raise BlpaError("Linklan: authentication failed (wrong PSK?)")

    # -- connection ------------------------------------------------------ #
    async def connect(self) -> None:
        dev = await self._find()
        self.name = dev.name or ""
        self.address = dev.address
        self.client = BleakClient(dev, timeout=self.timeout)
        await self.client.connect()
        await self.client.start_notify(NOTIFY, self._on_notify)
        await self._request(CMD_DEVICE, pb.enc_int(1, 1, always=True))   # getDeviceInfo
        self.channel = await self._open_channel()

    async def disconnect(self) -> None:
        if self.client:
            try:
                await self.client.stop_notify(NOTIFY)
            except Exception:
                pass
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    # -- SCARD bridge ---------------------------------------------------- #
    async def _open_channel(self, aid: str = ISDR_AID) -> int:
        body = (pb.enc_int(1, 1, always=True)
                + pb.enc_msg(2, pb.enc_str(1, aid) + pb.enc_int(2, 0)))
        rsp = await self._request(CMD_SCARD, body)
        result = pb.as_int(pb.first(pb.decode(rsp), 2, 0))
        if result != 0:
            # a leaked logical channel from a previous session blocks new ones
            log.info("Linklan: openChannel result=%s, releasing stale channels", result)
            for ch in range(1, 6):
                try:
                    await self._request(CMD_SCARD, pb.enc_int(1, 2, always=True) + pb.enc_int(3, ch))
                except BlpaError:
                    pass
                await asyncio.sleep(0.1)
            rsp = await self._request(CMD_SCARD, body)
            result = pb.as_int(pb.first(pb.decode(rsp), 2, 0))
            if result != 0:
                raise BlpaError(f"Linklan: openChannel failed (result={result})")
        return 4

    async def _transmit(self, apdu: bytes) -> bytes:
        cla, ins, p1, p2, lc = apdu[0], apdu[1], apdu[2], apdu[3], apdu[4]
        data = apdu[5:5 + lc]
        ta = (pb.enc_int(1, zz(self.channel)) + pb.enc_int(2, zz(cla))
              + pb.enc_int(3, zz(ins)) + pb.enc_int(4, zz(p1))
              + pb.enc_int(5, zz(p2)) + pb.enc_int(6, zz(len(data)))
              + pb.enc_str(7, data.hex().upper()))
        rsp = await self._request(CMD_SCARD, pb.enc_int(1, 3, always=True) + pb.enc_msg(4, ta))
        ta_rsp = pb.first(pb.decode(rsp), 4)
        if not ta_rsp:
            raise BlpaError("Linklan: no transmitApdu response")
        r = pb.decode(ta_rsp)
        sw1 = unzz(pb.as_int(pb.first(r, 1, 0)))
        sw2 = unzz(pb.as_int(pb.first(r, 2, 0)))
        return (pb.first(r, 3) or b"") + bytes([sw1 & 0xFF, sw2 & 0xFF])

    async def _transmit_wait(self, apdu: bytes) -> bytes:
        rsp = await self._transmit(apdu)
        while len(rsp) >= 2 and rsp[-2] == 0x61:
            rsp = await self._transmit(bytes([0x80, 0xC0, 0x00, 0x00, rsp[-1]]))
        return rsp

    async def store_data(self, cmd: bytes, max_block: int = MAX_BLOCK) -> bytes:
        """Send an ES10 command; returns the response TLV without the status word."""
        pos, block = 0, 0
        while True:
            rest = cmd[pos:]
            more = len(rest) > max_block
            chunk = rest[:max_block] if more else rest
            p1 = 0x11 if more else 0x91
            rsp = await self._transmit_wait(bytes([0x80, 0xE2, p1, block, len(chunk)]) + chunk)
            if rsp[-2:] == b"\x68\x81":          # channel gone: reopen and retry once
                log.info("Linklan: SW 6881, re-opening the logical channel")
                self.channel = await self._open_channel()
                rsp = await self._transmit_wait(bytes([0x80, 0xE2, p1, block, len(chunk)]) + chunk)
            body, sw = rsp[:-2], rsp[-2:]
            if more:
                if sw != b"\x90\x00":
                    raise BlpaError(f"Linklan: STORE DATA failed (SW {sw.hex()})")
                pos += max_block
                block += 1
                continue
            self.last_sw = sw
            if sw != b"\x90\x00" and sw[:1] != b"\x91":
                raise BlpaError(f"Linklan: command failed (SW {sw.hex()})")
            return body

    # -- card operations -------------------------------------------------- #
    async def eid(self) -> str:
        rsp = await self.store_data(tlv.cmd_eid())
        value = tlv.find(rsp, 0xBF3E, 0x5A)
        if value is None:
            raise BlpaError(f"Linklan: no EID ({rsp.hex()})")
        return tlv.bcd(value)

    async def profiles(self) -> List[Profile]:
        return tlv.parse_profiles(await self.store_data(tlv.cmd_profiles()))

    async def _op(self, cmd: bytes, tag: int) -> bool:
        rsp = await self.store_data(cmd)
        code = tlv.result_code(rsp, tag)
        if code != 0:
            raise BlpaError(f"Linklan: operation failed (code {code})")
        return True

    async def enable(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_enable(iccid), 0xBF31)

    async def disable(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_disable(iccid), 0xBF32)

    async def delete(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_delete(iccid), 0xBF33)

    async def nickname(self, iccid: str, value: str) -> bool:
        return await self._op(tlv.cmd_nickname(iccid, value), 0xBF29)

    async def info(self) -> CardInfo:
        rsp = await self._request(CMD_DEVICE, pb.enc_int(1, 1, always=True))
        msg = pb.decode(rsp)
        info = pb.first(msg, 3) or b""
        f = pb.decode(info)
        text = lambda k: (pb.first(f, k) or b"").decode("utf-8", "replace")  # noqa: E731
        return CardInfo(kind=self.kind, name=self.name, address=self.address,
                        eid=await self.eid(),
                        extra={"vendor": text(1), "imei": text(2), "sn": text(3),
                               "model": text(4), "scardMode": bool(pb.first(f, 6))})
