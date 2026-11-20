"""Offline tests for the SGP.22 download machinery (no card, no network).

    PYTHONPATH=src/py python src/py/tests/test_sgp22.py
"""
from __future__ import annotations

import asyncio
import sys

from blpa import tlv
from blpa import sgp22 as S


def test_activation_code():
    c = S.parse_activation_code("LPA:1$rsp.example.com$04386-AGYFT-A74Y8-3F815")
    assert c.smdp == "rsp.example.com", c
    assert c.matching_id == "04386-AGYFT-A74Y8-3F815", c
    assert c.oid == ""
    assert S.parse_activation_code("lpa:1$a.b$MID$x").oid == "x"
    for bad in ("", "1", "LPA:2$smdp$mid", "LPA:1$$mid", "nonsense"):
        try:
            S.parse_activation_code(bad)
        except S.BlpaError:
            pass
        else:
            raise AssertionError(f"{bad!r} should be rejected")


def test_der_offsets():
    bpp = S._synthetic_bpp()
    root = S.der_find(bpp, 0xBF36)
    assert root is not None and root.start == 0
    assert root.content_start == 4 and root.total_len == len(bpp)
    # a child keeps absolute offsets into the original buffer
    inner = S.der_find_in(root, 0xA3)
    assert inner is not None
    kids = S.der_parse(bpp, inner.content_start, inner.start + inner.total_len)
    assert kids and kids[0].start >= inner.content_start
    assert bpp[kids[0].start:kids[0].start + 2] == b"\x86\x20"


def test_segmentation():
    bpp = S._synthetic_bpp()
    frags = S.segment_bpp(bpp)
    labels = [label for _, label in frags]
    assert labels[0] == "initialiseSecureChannel", labels[:2]
    assert labels[1] == "configureISDP"
    assert labels[2] == "storeMetadata header"
    assert "replaceSessionKeys" in labels
    assert labels[labels.index("loadProfileElements header") + 1] == "loadProfileElements"
    # every slice must be a slice of the package (no re-encoding)
    for frag, _label in frags:
        assert frag in bpp
    # the first segment repeats the BF36 header, the rest must not
    assert frags[0][0].startswith(b"\xbf\x36")
    assert all(not f.startswith(b"\xbf\x36") for f, _ in frags[1:])
    assert len(frags) == 1 + 1 + 1 + 2 + 1 + 1 + 5      # as counted in the doc


def test_installation_result():
    ok = tlv.encode(0xBF37, tlv.encode(0xBF27,
        tlv.encode(0xBF2F, tlv.encode(0x80, b"\x05") + tlv.encode(0x5A, bytes.fromhex("8944012345678901234F")))
        + tlv.encode(0xA2, tlv.encode(0xA0, tlv.encode(0x80, b"\x00")))))
    r = S.parse_installation_result(ok)
    assert r["status"] == "success", r
    assert r["iccid"] == "8944012345678901234", r
    assert r["seq"] == 5

    bad = tlv.encode(0xBF37, tlv.encode(0xBF27,
        tlv.encode(0xA2, tlv.encode(0xA1, tlv.encode(0x80, b"\x01")))))
    assert S.parse_installation_result(bad)["status"] == "error"
    assert S.parse_installation_result(b"\x00\x01") == {"raw": "0001"}


def test_device_info_layout():
    """The IMEI must be a sibling of deviceCapabilities inside DeviceInfo."""
    sent = []

    class Fake:
        async def store_data(self, cmd):
            sent.append(cmd)
            return b"\xbf\x38\x00"

    eu = S.Euicc(Fake())
    asyncio.run(eu.authenticate_server(b"\x30\x00", b"\x5f\x37\x00", b"\x04\x00",
                                       b"\x30\x00", "MID-1", imei="123261291681006"))
    req = sent[0]
    assert req[:2] == b"\xbf\x38"
    ctx = S.der_find_in(S.der_parse(req)[0], 0xA0)
    kids = S.der_parse(req, ctx.content_start, ctx.start + ctx.total_len)
    assert [k.tag for k in kids] == [0x80, 0xA1], [hex(k.tag) for k in kids]
    assert kids[0].content == b"MID-1"
    dev = S.der_parse(req, kids[1].content_start, kids[1].start + kids[1].total_len)
    assert [k.tag for k in dev] == [0x80, 0xA1, 0x82], [hex(k.tag) for k in dev]
    assert dev[2].length == 8, "IMEI is 8 BCD bytes"

    # without an IMEI the field is simply absent, and the default TAC is used
    sent.clear()
    asyncio.run(eu.authenticate_server(b"\x30\x00", b"\x5f\x37\x00", b"\x04\x00",
                                       b"\x30\x00", "MID-1"))
    ctx = S.der_find_in(S.der_parse(sent[0])[0], 0xA0)
    dev = S.der_parse(sent[0], ctx.content_start, ctx.start + ctx.total_len)[1]
    assert [k.tag for k in S.der_parse(sent[0], dev.content_start, dev.start + dev.total_len)] == [0x80, 0xA1]


def test_bcd():
    # GSM 03.40 nibble swap: "12326129" -> 21 23 16 92
    assert S._tac("123261291681006") == bytes.fromhex("21231692")
    assert S._tac("") == bytes.fromhex("00000000")
    # 15 digits are F/0-padded to 8 bytes
    assert S._imei_bcd("123261291681006") == bytes.fromhex("2123169261180006")
    assert S._gsm_bcd("1234") == bytes.fromhex("2143")
    assert S._gsm_bcd("123") == bytes.fromhex("21f3")      # odd length -> F pad


def test_dry_run():
    out = S.dry_run_download("LPA:1$rsp.example.com$MID-1")
    assert out["smdp"] == "rsp.example.com"
    assert out["segments_over_block_limit"] == [], out
    assert len(out["segments"]) == 11 or len(out["segments"]) >= 10


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"{name[5:]:24s} OK")
            except AssertionError as exc:
                failed += 1
                print(f"{name[5:]:24s} FAIL  {exc}")
    sys.exit(1 if failed else 0)
