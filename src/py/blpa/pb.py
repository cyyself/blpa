"""Tiny protobuf codec (the subset the Linklan LPAd protocol needs)."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


class DecodeError(ValueError):
    pass


def _varint(n: int) -> bytes:
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_int(field: int, value: int, always: bool = False) -> bytes:
    if not value and not always:
        return b""
    return _varint(field << 3) + _varint(int(value))


def enc_bytes(field: int, value: bytes) -> bytes:
    if not value:
        return b""
    return _varint((field << 3) | 2) + _varint(len(value)) + bytes(value)


def enc_str(field: int, value: str) -> bytes:
    return enc_bytes(field, value.encode())


def enc_msg(field: int, value: bytes) -> bytes:
    return enc_bytes(field, value)


def decode(data: bytes) -> Dict[int, List[Any]]:
    out: Dict[int, List[Any]] = {}
    i = 0
    while i < len(data):
        key, i = _read_varint(data, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _read_varint(data, i)
        elif wire == 2:
            ln, i = _read_varint(data, i)
            value = data[i:i + ln]
            i += ln
        elif wire == 1:
            value = data[i:i + 8]; i += 8
        elif wire == 5:
            value = data[i:i + 4]; i += 4
        else:
            raise DecodeError(f"wire type {wire}")
        out.setdefault(field, []).append(value)
    return out


def _read_varint(data: bytes, i: int) -> Tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(data):
            raise DecodeError("truncated varint")
        b = data[i]; i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def first(msg: Dict[int, List[Any]], field: int, default=None):
    values = msg.get(field)
    return values[0] if values else default


def as_int(value) -> int:
    return int(value) if isinstance(value, int) else 0
