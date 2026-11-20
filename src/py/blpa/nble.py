"""9eSIM / NBLE-SIM writer (``nble``) — 3DES-authenticated framed APDU over Nordic UART.

Reverse-engineered from NekokoLPA2's ``NBLESimAdapter`` (MIT) and verified on
hardware (handshake + EID; that card had no profiles installed).  See
``protocol/nble.md``.

Link layout
    service 6e400001-b5a3-f393-e0a9-e50e24dcca9e
    write   6e400002-... (write-without-response)
    notify  6e400003-...

Handshake
    device -> 0xE0 || 3DES_ECB(challenge16)          (issued right after connect)
    host   -> 0xE0 || 3DES_ECB(plain with counter+1)  (counter at plain[7..8], LE)
    device -> 0xE0 90 00   (ok)       0xE6.. 6A86 = wrong password

APDUs
    body  = counter(1) || apdu
    frame = body || sum16(body)                      (big endian sum of bytes)
    sent in chunks: header = (last ? 0x20 : 0x00) | seq, then up to 100 bytes
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from bleak import BleakClient, BleakScanner

from . import tlv
from .base import BlpaError, Card, CardInfo, Profile

log = logging.getLogger("blpa.nble")

SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
NAME_PREFIXES = ("9esim", "esim_writer", "nble")
CHUNK = 100          # bytes per BLE write (frame header included below)


# --------------------------------------------------------------------------- #
# password / key derivation (NBLESimAdapter.calculatePasswordHex / _buildAuthKey)
# --------------------------------------------------------------------------- #
def password_from_name(name: str) -> str:
    """Default password: the last six characters of the name, reversed."""
    tail = name.strip()[-6:]
    return tail[::-1]


def password_hex(value: str) -> str:
    """Hex form used for the key: 6 hex chars pass through, anything else CRC24."""
    v = value.strip()
    if len(v) == 6 and all(c in "0123456789abcdefABCDEF" for c in v):
        return v.upper()
    crc = 0xB704CE
    for b in v.encode():
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return f"{crc & 0xFFFFFF:06X}"


def auth_key(device_name: str, password: Optional[str] = None) -> bytes:
    pw = password_hex(password) if password else password_hex(password_from_name(device_name))
    base = device_name[-2:] + pw
    return bytes.fromhex(base * 3 + "00000000")


# --------------------------------------------------------------------------- #
# 3DES-ECB (16-byte 2-key 3DES)
# --------------------------------------------------------------------------- #
def _tdes(data: bytes, key: bytes, decrypt: bool) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:                                        # cryptography >= 43
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except Exception:                           # pragma: no cover - older wheels
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    if len(key) == 16:                       # 2-key 3DES -> K1 K2 K1 (24 bytes)
        key = key + key[:8]
    c = Cipher(TripleDES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()


def sum16(data: bytes) -> int:
    return sum(data) & 0xFFFF


# --------------------------------------------------------------------------- #
# card
# --------------------------------------------------------------------------- #
class NbleCard(Card):
    """The current 9eSIM firmware (NBLE-SIM)."""

    kind = "9esim"

    def __init__(self, address: Optional[str] = None, name: Optional[str] = None,
                 password: Optional[str] = None, chunk: int = CHUNK):
        self.address = address
        self.name_filter = (name or "").lower()
        self.password = password
        self.chunk = chunk
        self.client: Optional[BleakClient] = None
        self.name = ""
        self._buf = bytearray()
        self._packets: List[bytes] = []
        self._frame_done = asyncio.Event()
        self._counter = 0
        self._authkey: bytes = b""

    # -- link ----------------------------------------------------------- #
    async def _find(self):
        if self.address:
            target = self.address.upper()
            for d in await BleakScanner.discover(timeout=20):
                if d.address.upper() == target:
                    return d
            raise BlpaError(f"device {self.address} not found")
        want = self.name_filter
        deadline = asyncio.get_event_loop().time() + 25
        while asyncio.get_event_loop().time() < deadline:
            for d in await BleakScanner.discover(timeout=8):
                n = (d.name or "").lower()
                if want and want in n:
                    return d
                if not want and any(n.startswith(p) for p in NAME_PREFIXES):
                    return d
        raise BlpaError("no 9eSIM writer found (looked for "
                        + (want or "/".join(NAME_PREFIXES)) + ")")

    def _on_notify(self, _char, data: bytearray) -> None:
        data = bytes(data)
        if not data:
            return
        self._packets.append(data)                      # raw packet, header included
        self._buf.extend(data[1:])                      # payload only
        if data[0] & 0x20:                              # last frame of the reply
            self._frame_done.set()

    async def _wait(self, timeout: float = 10.0) -> tuple[List[bytes], bytes]:
        """Wait for a complete reply; returns (raw packets, payload)."""
        self._buf.clear()
        self._packets.clear()
        self._frame_done.clear()
        try:
            await asyncio.wait_for(self._frame_done.wait(), timeout)
        except asyncio.TimeoutError as exc:
            raise BlpaError("9eSIM: no reply from the writer") from exc
        packets, payload = list(self._packets), bytes(self._buf)
        self._packets.clear()
        self._buf.clear()
        return packets, payload

    async def _write(self, payload: bytes) -> None:
        chunk = self.chunk - 1
        seq = 0
        for off in range(0, len(payload), chunk):
            part = payload[off:off + chunk]
            last = off + chunk >= len(payload)
            header = (0x20 if last else 0x00) | (seq & 0x1F)
            await self.client.write_gatt_char(WRITE, bytes([header]) + part, response=False)
            seq = (seq + 1) & 0x1F

    async def _handshake(self) -> None:
        packets, _ = await self._wait(6.0)
        frame = packets[0] if packets else b""
        if len(frame) < 17 or frame[0] != 0xE0:
            raise BlpaError(f"9eSIM: unexpected greeting {frame.hex()}")
        block = frame[1:17]
        plain = bytearray(_tdes(block, self._authkey, decrypt=True))
        counter = (plain[7] | (plain[8] << 8)) & 0xFFFF
        counter = (counter + 1) & 0xFFFF
        plain[7] = counter & 0xFF
        plain[8] = (counter >> 8) & 0xFF
        # the handshake reply is a single packet whose 0xE0 byte *is* the frame
        # header, so it must not go through the normal chunker
        await self.client.write_gatt_char(
            WRITE, bytes([0xE0]) + _tdes(bytes(plain), self._authkey, decrypt=False),
            response=False)
        packets, _ = await self._wait(6.0)
        ack = packets[0] if packets else b""
        sw = ack[1:3].hex().upper() if len(ack) >= 3 else ack.hex()
        if sw == "6A86":
            raise BlpaError("9eSIM: wrong password (6A86)")
        if sw != "9000":
            raise BlpaError(f"9eSIM: handshake failed ({sw})")
        log.info("9eSIM handshake ok (device counter was %d)", counter - 1)

    async def connect(self) -> None:
        dev = await self._find()
        self.name = dev.name or ""
        self.address = dev.address
        self._authkey = auth_key(self.name, self.password)
        self.client = BleakClient(dev, timeout=30)
        await self.client.connect()
        await self.client.start_notify(NOTIFY, self._on_notify)
        await self._handshake()
        self._counter = 0

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

    # -- APDU ----------------------------------------------------------- #
    async def apdu(self, apdu: bytes, timeout: float = 30.0) -> bytes:
        body = bytes([self._counter & 0xFF]) + apdu
        self._counter = (self._counter + 1) & 0xFF
        s = sum16(body)
        await self._write(body + bytes([s >> 8, s & 0xFF]))
        _, buf = await self._wait(timeout)
        if len(buf) < 3:
            raise BlpaError(f"9eSIM: short response {buf.hex()}")
        raw, checksum = buf[:-2], (buf[-2] << 8) | buf[-1]
        if sum16(raw) != checksum:
            raise BlpaError(f"9eSIM: checksum mismatch ({checksum:04X})")
        return raw[1:]

    async def transmit(self, apdu: bytes, chained: bool = True) -> bytes:
        """APDU with GET RESPONSE handling (61xx)."""
        rsp = await self.apdu(apdu)
        out = b""
        while len(rsp) >= 2 and rsp[-2] == 0x61:
            out += rsp[:-2]
            rsp = await self.apdu(bytes([0x80 | (0x00), 0xC0, 0x00, 0x00, rsp[-1]]))
        return out + rsp

    async def store_data(self, tlv_cmd: bytes, max_block: int = 239, channel: int = 0) -> bytes:
        cla = 0x80 | (channel & 0x03)
        pos, block = 0, 0
        while True:
            rest = tlv_cmd[pos:]
            more = len(rest) > max_block
            chunk = rest[:max_block] if more else rest
            p1 = 0x11 if more else 0x91
            rsp = await self.transmit(bytes([cla, 0xE2, p1, block, len(chunk)]) + chunk)
            body, sw = rsp[:-2], rsp[-2:]
            if more:
                if sw != b"\x90\x00":
                    raise BlpaError(f"9eSIM: STORE DATA failed (SW {sw.hex()})")
                pos += max_block
                block += 1
                continue
            self.last_sw = sw
            if sw != b"\x90\x00" and sw[:1] != b"\x91":
                raise BlpaError(f"9eSIM: command failed (SW {sw.hex()})")
            return body

    # -- card operations ------------------------------------------------ #
    async def _select(self) -> None:
        rsp = await self.transmit(bytes.fromhex("00A4040010" + ISDR_AID))
        if not rsp.endswith(b"\x90\x00"):
            raise BlpaError(f"9eSIM: SELECT ISD-R failed ({rsp.hex()})")

    async def _ensure(self) -> None:
        if not getattr(self, "_selected", False):
            await self._select()
            self._selected = True

    async def eid(self) -> str:
        await self._ensure()
        rsp = await self.store_data(tlv.cmd_eid())
        value = tlv.find(rsp, 0xBF3E, 0x5A)
        if value is None:
            raise BlpaError(f"9eSIM: no EID in {rsp.hex()}")
        return tlv.bcd(value)

    async def profiles(self) -> List[Profile]:
        await self._ensure()
        return tlv.parse_profiles(await self.store_data(tlv.cmd_profiles()))

    async def _op(self, cmd: bytes, tag: int) -> bool:
        await self._ensure()
        code = tlv.result_code(await self.store_data(cmd), tag)
        if code != 0:
            raise BlpaError(f"9eSIM: operation failed (code {code})")
        return True

    async def enable(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_enable(iccid), 0xBF31)

    async def disable(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_disable(iccid), 0xBF32)

    async def delete(self, iccid: str) -> bool:
        return await self._op(tlv.cmd_delete(iccid), 0xBF33)

    async def nickname(self, iccid: str, value: str) -> bool:
        return await self._op(tlv.cmd_nickname(iccid, value), 0xBF29)

    async def set_name_and_password(self, name_suffix: str, password: str) -> None:
        """Change the writer's BLE name suffix **and** its password together.

        Vendor command seen in NekokoLPA2 (`_performUpdate`):
        ``30 27 00 00 09 11 11 11 <newSuffix 3B> <passwordHex 3B>`` with CLA
        ``0x30`` and a ``0x80`` fallback.  Both halves are 6 hex characters, so
        the suffix (which is the tail of the advertised name) and the password
        can only be hex strings; a non-hex password is reduced with CRC24.

        The card renames itself, so the host must reconnect using the new name
        (and the new password) afterwards.
        """
        suffix = name_suffix.strip().upper()
        if len(suffix) != 6 or any(c not in "0123456789ABCDEF" for c in suffix):
            raise BlpaError("9eSIM name suffix must be 6 hex characters")
        pw = password_hex(password)
        data = bytes.fromhex("111111" + suffix + pw)      # 9 bytes
        last = b""
        for cla in (0x30, 0x80):
            last = await self.transmit(bytes([cla, 0x27, 0x00, 0x00, len(data)]) + data)
            if last.endswith(b"\x90\x00") or last.endswith(b"\x61\x00"):
                return
            if last.endswith(b"\x6e\x00"):
                continue                                   # CLA unsupported, try 0x80
            break
        raise BlpaError(f"9eSIM: set name/password failed ({last.hex()})")

    async def info(self) -> CardInfo:
        # report the *derivable* default, never the password actually used (it may
        # be custom and must not end up in logs)
        return CardInfo(kind=self.kind, name=self.name, address=self.address,
                        eid=await self.eid(),
                        extra={"defaultPassword": password_from_name(self.name)})
