"""BeeSIM readers — grouped APDU framing over GATT service 0xAE30.

Protocol from the official web LPA (https://beeesim.com/ble/, "BeeSIM Web
v2.1.4") and `cyyself/beeesim-api`.  **Verified on hardware** (EID, profile list, rename); see protocol/beeesim.md.

    BLE:      service 0000ae30-0000-1000-8000-00805f9b34fb, one write and one
              notify characteristic, device name starts with "BeeSIM"
    framing:  packet = [total_groups, group_index(1-based)] + up to 18 bytes
    payload:  a plain ISO-7816 APDU; responses come back the same way
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from bleak import BleakClient, BleakScanner

from . import tlv
from .base import BlpaError, Card, CardInfo, Profile

log = logging.getLogger("blpa.beeesim")

SERVICE_UUID = "0000ae30-0000-1000-8000-00805f9b34fb"
NAME_PREFIX = "beesim"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
GROUP_PAYLOAD = 18
STORE_MAX_LC = 239
LOGICAL_CHANNEL = 1
TERMINAL_CAPABILITIES = "80AA00000AA9088100820101830107"


class BeeSimCard(Card):
    kind = "beeesim"

    def __init__(self, address: Optional[str] = None, name: Optional[str] = None,
                 timeout: float = 20.0):
        self.address = address
        self.name_filter = (name or "").lower()
        self.timeout = timeout
        self.client: Optional[BleakClient] = None
        self.name = ""
        self.write_uuid = ""
        self.notify_uuid = ""
        self.channel = LOGICAL_CHANNEL
        self._buf = bytearray()
        self._done = asyncio.Event()

    # -- link ------------------------------------------------------------ #
    async def _find(self):
        if self.address:
            for d in await BleakScanner.discover(timeout=20):
                if d.address.upper() == self.address.upper():
                    return d
            raise BlpaError(f"device {self.address} not found")
        want = self.name_filter or NAME_PREFIX
        for _ in range(3):
            for d in await BleakScanner.discover(timeout=8):
                if want in (d.name or "").lower():
                    return d
        raise BlpaError(f"no BeeSIM reader found (name contains {want!r})")

    def _on_notify(self, _char, data: bytearray) -> None:
        data = bytes(data)
        if not data:
            self._done.set()
            return
        total, index = data[0], data[1]
        if index == 1:
            self._buf.clear()
        self._buf.extend(data[2:])
        if index >= total:
            self._done.set()

    async def _send(self, apdu: bytes) -> bytes:
        if not self.client:
            raise BlpaError("not connected")
        groups = [apdu[i:i + GROUP_PAYLOAD] for i in range(0, len(apdu), GROUP_PAYLOAD)] or [b""]
        self._buf.clear()
        self._done.clear()
        for idx, group in enumerate(groups, 1):
            await self.client.write_gatt_char(
                self.write_uuid, bytes([len(groups), idx]) + group, response=False)
        try:
            await asyncio.wait_for(self._done.wait(), timeout=self.timeout)
        except asyncio.TimeoutError as exc:
            raise BlpaError("BeeSIM: no reply") from exc
        return bytes(self._buf)

    async def connect(self) -> None:
        dev = await self._find()
        self.name = dev.name or ""
        self.address = dev.address
        self.client = BleakClient(dev, timeout=30)
        await self.client.connect()
        for service in self.client.services:
            if service.uuid.lower() == SERVICE_UUID:
                for ch in service.characteristics:
                    props = [p.lower() for p in ch.properties]
                    if "notify" in props or "indicate" in props:
                        self.notify_uuid = ch.uuid
                    elif "write" in props or "write-without-response" in props:
                        self.write_uuid = ch.uuid
        if not self.write_uuid or not self.notify_uuid:
            raise BlpaError("BeeSIM: AE30 service not usable")
        await self.client.start_notify(self.notify_uuid, self._on_notify)
        await self._init_card()

    async def disconnect(self) -> None:
        if self.client:
            try:
                await self.client.stop_notify(self.notify_uuid)
            except Exception:
                pass
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    # -- APDU ------------------------------------------------------------ #
    async def _command(self, apdu: bytes) -> bytes:
        rsp = await self._send(apdu)
        if len(rsp) >= 2 and rsp[-2] == 0x68 and rsp[-1] == 0x81:      # channel gone
            await self._init_card()
            rsp = await self._send(apdu)
        return rsp

    async def _get_response(self, le: int, cla: int) -> bytes:
        out = b""
        while True:
            rsp = await self._command(bytes([cla, 0xC0, 0x00, 0x00, le & 0xFF]))
            if len(rsp) < 2:
                raise BlpaError(f"BeeSIM: short GET RESPONSE {rsp.hex()}")
            body, sw1, sw2 = rsp[:-2], rsp[-2], rsp[-1]
            out += body
            if sw1 == 0x61:
                le = sw2
                continue
            if sw1 == 0x90:
                return out + bytes([sw1, sw2])       # keep the SW for the caller
            raise BlpaError(f"BeeSIM: GET RESPONSE SW {sw1:02X}{sw2:02X}")

    async def _init_card(self) -> None:
        """Select the ISD-R applet.

        Measured on `BeeSIM-000000`: the reader does **not** implement
        MANAGE CHANNEL (`00 70 00 01 00` -> 6A86); the applet is selected with
        CLA = channel (0x01) and a pending `61 xx` is fetched with the *same*
        CLA, while ES10 traffic on the same applet uses CLA 0x81.
        """
        ch = self.channel
        try:
            await self._command(bytes.fromhex(TERMINAL_CAPABILITIES))
        except BlpaError:
            pass
        rsp = await self._command(bytes([ch, 0xA4, 0x04, 0x00, len(ISDR_AID) // 2])
                                  + bytes.fromhex(ISDR_AID))
        if rsp[:1] == b"\x61":
            rsp = await self._get_response(rsp[1], cla=ch)
        if not rsp.endswith(b"\x90\x00"):
            raise BlpaError(f"BeeSIM: SELECT ISD-R failed ({rsp.hex()})")

    async def store_data(self, cmd: bytes) -> bytes:
        cla = (self.channel & 0x0F) | 0x80
        pos = block = 0
        while True:
            rest = cmd[pos:]
            more = len(rest) > STORE_MAX_LC
            chunk = rest[:STORE_MAX_LC] if more else rest
            p1 = 0x11 if more else 0x91
            rsp = await self._command(bytes([cla, 0xE2, p1, block, len(chunk)]) + chunk)
            if rsp[:1] == b"\x61":            # data pending: fetch it, keep the SW
                rsp = await self._get_response(rsp[1], cla=cla)
            body, sw = rsp[:-2], rsp[-2:]
            if more:
                if sw != b"\x90\x00":
                    raise BlpaError(f"BeeSIM: STORE DATA failed (SW {sw.hex()})")
                pos += STORE_MAX_LC
                block += 1
                continue
            self.last_sw = sw
            if sw != b"\x90\x00" and sw[:1] != b"\x91":
                raise BlpaError(f"BeeSIM: command failed (SW {sw.hex()})")
            return body

    # -- card operations -------------------------------------------------- #
    async def eid(self) -> str:
        value = tlv.find(await self.store_data(tlv.cmd_eid()), 0xBF3E, 0x5A)
        if value is None:
            raise BlpaError("BeeSIM: no EID")
        return tlv.bcd(value)

    async def profiles(self) -> List[Profile]:
        return tlv.parse_profiles(await self.store_data(tlv.cmd_profiles()))

    async def _op(self, cmd: bytes, tag: int) -> bool:
        code = tlv.result_code(await self.store_data(cmd), tag)
        if code != 0:
            raise BlpaError(f"BeeSIM: operation failed (code {code})")
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
        return CardInfo(kind=self.kind, name=self.name, address=self.address,
                        eid=await self.eid())
