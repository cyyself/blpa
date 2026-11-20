"""Minimal BER-TLV codec plus the SGP.22 bits the three cards need."""
from __future__ import annotations

from typing import Dict, List, Tuple

from .base import Profile

# --- encode / decode ------------------------------------------------------- #
def encode(tag, *children: bytes) -> bytes:
    """BER-TLV: tag (int or bytes) + definite length + payload."""
    tag = tag if isinstance(tag, (bytes, bytearray)) else _tag_bytes(tag)
    body = b"".join(c if isinstance(c, bytes) else bytes(c) for c in children)
    return bytes(tag) + _len(len(body)) + body


def _tag_bytes(tag: int) -> bytes:
    if tag <= 0xFF:
        return bytes([tag])
    if tag <= 0xFFFF:
        return bytes([tag >> 8, tag & 0xFF])
    return bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def decode(data: bytes, start: int = 0, end: int | None = None) -> List[Tuple[int, bytes]]:
    """Parse a TLV stream into [(tag, value)]; tags keep their multi-byte form."""
    out: List[Tuple[int, bytes]] = []
    end = len(data) if end is None else end
    i = start
    while i < end:
        first = data[i]
        i += 1
        tag = first
        if first & 0x1F == 0x1F:                     # multi-byte tag
            while i < end:
                b = data[i]; i += 1
                tag = (tag << 8) | b
                if not b & 0x80:
                    break
        if i >= end:
            break
        ln = data[i]; i += 1
        if ln == 0x81:
            ln = data[i]; i += 1
        elif ln == 0x82:
            ln = (data[i] << 8) | data[i + 1]; i += 2
        elif ln == 0x83:
            ln = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]; i += 3
        out.append((tag, data[i:i + ln]))
        i += ln
    return out


def to_dict(data: bytes) -> Dict[int, bytes]:
    return dict(decode(data))


def find(data: bytes, *tags: int):
    """Walk nested TLVs along ``tags`` and return the last value."""
    value = data
    for tag in tags:
        hit = to_dict(value).get(tag) if value else None
        if hit is None:
            return None
        value = hit
    return value


# --- BCD helpers ----------------------------------------------------------- #
def bcd(value: bytes, swap: bool = False) -> str:
    digits = []
    for byte in value:
        nibbles = (byte & 0x0F, byte >> 4) if swap else (byte >> 4, byte & 0x0F)
        for n in nibbles:
            if n == 0x0F:
                continue
            digits.append(f"{n:X}")
    return "".join(digits)


def to_bcd(text: str, swap: bool = False) -> bytes:
    s = text.strip().upper().replace(" ", "")
    if len(s) % 2:
        s += "F"
    raw = bytes.fromhex(s)
    if not swap:
        return raw
    return bytes(((b & 0x0F) << 4) | (b >> 4) for b in raw)


# --- ES10 command builders (shared by all three backends) ------------------ #
def cmd_eid() -> bytes:
    return encode(0xBF3E, encode(0x5C, b"\x5A"))


def cmd_profiles() -> bytes:
    return encode(0xBF2D, encode(0x5C, bytes([0x5A, 0x90, 0x91, 0x92, 0xB7, 0x9F, 0x70, 0x95, 0x99])))


def _profile_body(iccid: str, *extra: bytes) -> bytes:
    """Profile identifier in a [0] container — required by the Linklan firmware,
    accepted by the others, so all three use the same encoding."""
    body = encode(0x5A, to_bcd(iccid, swap=True))
    for item in extra:
        body += item
    return encode(0xA0, body)


def cmd_enable(iccid: str) -> bytes:
    return encode(0xBF31, _profile_body(iccid, encode(0x81, b"\xFF")))


def cmd_disable(iccid: str) -> bytes:
    return encode(0xBF32, _profile_body(iccid))


def cmd_delete(iccid: str) -> bytes:
    return encode(0xBF33, _profile_body(iccid))


def cmd_nickname(iccid: str, nickname: str) -> bytes:
    return encode(0xBF29, encode(0x5A, to_bcd(iccid, swap=True)),
                  encode(0x90, nickname.encode()))


def cmd_notifications() -> bytes:
    return encode(0xBF28, b"")


# --- result parsing -------------------------------------------------------- #
def result_code(rsp: bytes, tag: int) -> int:
    body = to_dict(rsp).get(tag, b"")
    return to_dict(body).get(0x80, b"\xFF")[0] if body else 0xFF


def parse_profiles(rsp: bytes) -> List[Profile]:
    out: List[Profile] = []
    body = to_dict(rsp).get(0xBF2D, b"")
    container = to_dict(body).get(0xA0, b"")
    for tag, value in decode(container) if container else []:
        if tag != 0xE3:
            continue
        f = to_dict(value)
        out.append(Profile(
            iccid=bcd(f.get(0x5A, b""), swap=True),
            enabled=f.get(0x9F70, b"\x00") == b"\x01",
            nickname=f.get(0x90, b"").decode("utf-8", "replace"),
            name=f.get(0x91, b"").decode("utf-8", "replace"),
            provider=f.get(0x92, b"").decode("utf-8", "replace"),
            profile_class=f.get(0x95, b"\x00")[0],
        ))
    return out
