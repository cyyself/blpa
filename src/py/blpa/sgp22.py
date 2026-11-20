"""GSMA SGP.22 profile download, shared by all three card backends.

The card side of a download is plain ES10b: every backend already exposes
``store_data(tlv)`` (STORE DATA with ``11/91`` chaining over the ISD-R), so the
flow below is card independent — only the APDU transport differs, and that is
hidden behind :meth:`blpa.base.Card.store_data`.

    activation code LPA:1$<smdp>$<matchingId>[$<oid>]
        └─ ES10b GetEUICCChallenge (BF2E) + GetEuiccInfo1 (BF20)
        └─ ES9+  initiateAuthentication            -> serverSigned1 …
        └─ ES10b AuthenticateServer (BF38)         -> authenticateServerResponse
        └─ ES9+  authenticateClient                -> smdpSigned2 …
        └─ ES10b PrepareDownload (BF21)            -> prepareDownloadResponse
        └─ ES9+  getBoundProfilePackage            -> boundProfilePackage (BF36)
        └─ ES10b LoadBoundProfilePackage, segmented (2.5.5)
        └─ ES9+  handleNotification + ES10b NotificationSent (BF30)

The SM-DP+ certificate chain is issued by the GSMA CI, not by a public web CA,
so a GSMA root bundle is shipped next to this module (``certs/``).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import tlv
from .base import BlpaError, Card

log = logging.getLogger("blpa.sgp22")

TIMEOUT = 60

# GSMA eSIM PKI roots (mirrors the certificate issuers published by the GSMA;
# the bundle is the one from the osmocom eUICC manual).
GSMA_CA_BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "certs", "gsma-rsp-ci-bundle.pem")


def _ca_bundle():
    """System/public CAs plus the GSMA eSIM roots."""
    try:
        import certifi
        public = certifi.where()
    except Exception:  # pragma: no cover
        public = None
    if not os.path.exists(GSMA_CA_BUNDLE):
        return public or True
    if not public:
        return GSMA_CA_BUNDLE
    combined = GSMA_CA_BUNDLE + ".combined.pem"
    try:
        if (not os.path.exists(combined)
                or os.path.getmtime(combined) < os.path.getmtime(GSMA_CA_BUNDLE)):
            with open(combined, "w") as out:
                out.write(open(public).read())
                out.write("\n")
                out.write(open(GSMA_CA_BUNDLE).read())
        return combined
    except OSError:  # pragma: no cover - read-only install
        return public


# --------------------------------------------------------------------------- #
# activation code
# --------------------------------------------------------------------------- #
@dataclass
class ActivationCode:
    smdp: str
    matching_id: str
    oid: str = ""
    raw: str = ""


def parse_activation_code(code: str) -> ActivationCode:
    code = (code or "").strip()
    if code.upper().startswith("LPA:"):
        code = code[4:]
    parts = code.split("$")
    if len(parts) < 3 or parts[0] != "1" or not parts[1] or not parts[2]:
        raise BlpaError(f"unsupported activation code: {code!r} "
                        "(expected LPA:1$<smdp>$<matchingId>)")
    return ActivationCode(smdp=parts[1], matching_id=parts[2],
                          oid=parts[3] if len(parts) > 3 else "", raw=code)


# --------------------------------------------------------------------------- #
# DER helpers (absolute offsets: needed to slice the bound profile package)
# --------------------------------------------------------------------------- #
@dataclass
class Node:
    tag: int
    start: int          # offset of the tag byte
    header_len: int     # tag + length bytes
    length: int         # content length
    data: bytes

    @property
    def content_start(self) -> int:
        return self.start + self.header_len

    @property
    def total_len(self) -> int:
        return self.header_len + self.length

    @property
    def content(self) -> bytes:
        return self.data[self.content_start:self.start + self.total_len]


def der_parse(data: bytes, start: int = 0, end: Optional[int] = None) -> List[Node]:
    end = len(data) if end is None else end
    nodes: List[Node] = []
    pos = start
    while pos < end:
        tag_start = pos
        tag = data[pos]
        pos += 1
        if tag & 0x1F == 0x1F:
            if pos >= end:
                break
            tag = (tag << 8) | data[pos]
            pos += 1
        if pos >= end:
            break
        ln = data[pos]
        pos += 1
        if ln & 0x80:
            nbytes = ln & 0x7F
            if nbytes == 0 or pos + nbytes > end:
                break
            ln = int.from_bytes(data[pos:pos + nbytes], "big")
            pos += nbytes
        nodes.append(Node(tag=tag, start=tag_start, header_len=pos - tag_start,
                          length=ln, data=data))
        pos += ln
    return nodes


def der_find(data: bytes, tag: int, start: int = 0,
             end: Optional[int] = None) -> Optional[Node]:
    for node in der_parse(data, start, end):
        if node.tag == tag:
            return node
    return None


def der_find_in(node: Node, tag: int) -> Optional[Node]:
    return der_find(node.data, tag, node.content_start, node.start + node.total_len)


def _tlv(tag: int, value: bytes) -> bytes:
    """One BER-TLV element with a (possibly two byte) tag."""
    return tlv.encode(tag, value)


# --------------------------------------------------------------------------- #
# ES9+ (SM-DP+ REST API)
# --------------------------------------------------------------------------- #
class SmdpError(RuntimeError):
    pass


class Smdp:
    def __init__(self, address: str, timeout: int = TIMEOUT, verify=None):
        self.address = address.strip()
        self.base = f"https://{self.address}/gsma/rsp2/es9plus"
        self.timeout = timeout
        import requests                      # imported here so `info`/`eid` work without it
        self.session = requests.Session()
        if verify is None:
            verify = os.environ.get("BLPA_CA_BUNDLE") or _ca_bundle()
        self.verify = verify

    def _post(self, endpoint: str, payload: dict, include_smdp: bool = False) -> dict:
        import requests
        url = f"{self.base}/{endpoint}"
        log.info("POST %s", url)
        body = dict(payload)
        if include_smdp:
            body.setdefault("smdpAddress", self.address)
        try:
            rsp = self.session.post(url, json=body, timeout=self.timeout,
                                    verify=self.verify,
                                    headers={"Content-Type": "application/json",
                                             "User-Agent": "blpa/0.1",
                                             "X-Admin-Protocol": "gsma/rsp/v2.2.0"})
        except requests.RequestException as exc:
            raise SmdpError(f"{endpoint}: {exc}") from exc
        if rsp.status_code == 204 or (rsp.status_code == 200 and not rsp.content.strip()):
            # SGP.22 6.3: handleNotification succeeds with HTTP 204, empty body.
            return {}
        if rsp.status_code != 200:
            raise SmdpError(f"{endpoint}: HTTP {rsp.status_code}: {rsp.text[:300]}")
        try:
            data = rsp.json()
        except ValueError as exc:
            raise SmdpError(f"{endpoint}: invalid JSON response") from exc
        header = data.get("header") or {}
        if header.get("functionExecutionStatus", {}).get("status") == "Failed":
            status = header["functionExecutionStatus"]
            raise SmdpError(f"{endpoint}: {status.get('status', 'Failed')}: "
                            f"{status.get('statusCodeData', {})}")
        return data

    # -- endpoints ------------------------------------------------------ #
    def initiate_authentication(self, euicc_challenge: bytes, euicc_info1: bytes,
                                matching_id: str) -> dict:
        return self._post("initiateAuthentication", {
            "euiccChallenge": _b64(euicc_challenge),
            "euiccInfo1": _b64(euicc_info1),
            "matchingId": matching_id,
        }, include_smdp=True)

    def authenticate_client(self, transaction_id: str, auth_server_response: bytes) -> dict:
        return self._post("authenticateClient", {
            "transactionId": transaction_id,
            "authenticateServerResponse": _b64(auth_server_response),
        })

    def get_bound_profile_package(self, transaction_id: str,
                                  prepare_download_response: bytes) -> bytes:
        data = self._post("getBoundProfilePackage", {
            "transactionId": transaction_id,
            "prepareDownloadResponse": _b64(prepare_download_response),
        })
        bpp = data.get("boundProfilePackage")
        if not bpp:
            raise SmdpError("getBoundProfilePackage: no boundProfilePackage")
        return base64.b64decode(_clean_b64(bpp))

    def handle_notification(self, pending_notification: bytes,
                            transaction_id: Optional[str] = None) -> dict:
        body: dict = {"pendingNotification": _b64(pending_notification)}
        if transaction_id:
            body["transactionId"] = transaction_id
        return self._post("handleNotification", body)


def _clean_b64(s: str) -> str:
    s = "".join(s.split())
    return s + "=" * (-len(s) % 4)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --------------------------------------------------------------------------- #
# ES10b commands (card side)
# --------------------------------------------------------------------------- #
class Euicc:
    """ES10b commands used during a download, over any backend's STORE DATA."""

    def __init__(self, card: Card):
        self.card = card

    async def es10(self, request_tlv: bytes, what: str = "ES10") -> bytes:
        try:
            return await self.card.store_data(request_tlv)
        except BlpaError as exc:
            raise BlpaError(f"{what}: {exc}") from exc

    async def info1(self) -> bytes:
        """EuiccInfo1 as [APPLICATION 32] (BF20), which is what the SM-DP+ wants."""
        try:
            rsp = await self.es10(bytes.fromhex("BF2000"), "GetEuiccInfo1")
            node = der_parse(rsp)
            if node and node[0].tag == 0xBF20:
                return rsp
        except BlpaError:
            pass
        # several firmwares answer BF3C; re-tag the same content as BF20
        rsp = await self.es10(bytes.fromhex("BF3C00"), "GetEuiccInfo1")
        node = der_parse(rsp)
        if not node or node[0].tag != 0xBF3C:
            raise BlpaError(f"GetEuiccInfo1: unexpected response {rsp.hex()}")
        return _tlv(0xBF20, node[0].content)

    async def info2(self) -> bytes:
        return await self.es10(bytes.fromhex("BF2200"), "GetEuiccInfo2")

    async def challenge(self) -> bytes:
        rsp = await self.es10(_tlv(0xBF2E, b""), "GetEUICCChallenge")
        node = der_find(rsp, 0xBF2E)
        if node is None:
            raise BlpaError(f"GetEUICCChallenge: no BF2E in {rsp.hex()}")
        inner = der_find_in(node, 0x80)
        if inner is None:
            raise BlpaError("GetEUICCChallenge: no challenge value (80)")
        return inner.content

    async def authenticate_server(self, server_signed1: bytes, server_signature1: bytes,
                                 euicc_ci_pkid: bytes, server_certificate: bytes,
                                 matching_id: str, imei: str = "") -> bytes:
        # CtxParamsForCommonAuthentication ::= SEQUENCE {
        #     matchingId UTF8String OPTIONAL, deviceInfo DeviceInfo }
        # DeviceInfo ::= SEQUENCE { tac Octet4, deviceCapabilities, imei Octet8 OPTIONAL }
        # AUTOMATIC TAGS: tac [0]=80, deviceCapabilities [1]=A1, imei [2]=82 — the
        # IMEI is a *sibling* of deviceCapabilities, not a child (getting this
        # wrong makes the card answer "authenticateClient 1.6/2.1 Invalid").
        dev = _tlv(0x80, _tac(imei) if imei else bytes.fromhex("35290611"))
        dev += _tlv(0xA1, b"")                     # no optional capabilities claimed
        if imei:
            dev += _tlv(0x82, _imei_bcd(imei))
        ctx = _tlv(0x80, matching_id.encode()) + _tlv(0xA1, dev)
        body = (server_signed1 + server_signature1 + euicc_ci_pkid
                + server_certificate + _tlv(0xA0, ctx))
        return await self.es10(_tlv(0xBF38, body), "AuthenticateServer")

    async def prepare_download(self, smdp_signed2: bytes, smdp_signature2: bytes,
                               smdp_certificate: bytes,
                               confirmation_code: Optional[str] = None) -> bytes:
        body = smdp_signed2
        if confirmation_code:
            transaction_id = der_find(smdp_signed2, 0x30)
            tid = der_find_in(transaction_id, 0x80) if transaction_id else None
            h = hashlib.sha256(confirmation_code.encode()).digest()
            if tid is not None:
                h = hashlib.sha256(h + tid.content).digest()
            body += smdp_signature2 + _tlv(0x04, h) + smdp_certificate
        else:
            body += smdp_signature2 + smdp_certificate
        return await self.es10(_tlv(0xBF21, body), "PrepareDownload")

    async def load_bpp(self, bpp: bytes, on_step=None) -> Optional[bytes]:
        """Load a bound profile package, segmented like the reference LPA."""
        fragments = segment_bpp(bpp)
        log.info("loading BPP in %d segments (%d bytes)", len(fragments), len(bpp))
        result = None
        for index, (fragment, label) in enumerate(fragments):
            rsp = await self.es10(fragment, f"LoadBoundProfilePackage[{index}:{label}]")
            if on_step:
                on_step(index, len(fragments), label, len(fragment))
            if rsp:
                result = rsp
                log.info("BPP segment %d/%d (%s) returned %d bytes",
                         index + 1, len(fragments), label, len(rsp))
        return result

    # ProfileManagementOperation ::= BIT STRING { install(0), enable(1),
    #                                            disable(2), delete(3) }
    PMO_NAMES = {0: "install", 1: "enable", 2: "disable", 3: "delete"}

    @classmethod
    def _pmo_name(cls, bits: bytes) -> str:
        if not bits:
            return "?"
        unused, body = bits[0], bits[1:]
        value = int.from_bytes(body, "big") if body else 0
        width = len(body) * 8
        for index in range(width - unused):
            if value & (1 << (width - 1 - index)):
                return cls.PMO_NAMES.get(index, f"bit{index}")
        return "none"

    async def list_notifications(self) -> List[dict]:
        rsp = await self.es10(_tlv(0xBF28, b""), "ListNotification")
        root = der_find(rsp, 0xBF28)
        if root is None:
            return []
        entries = der_find_in(root, 0xA0)
        out: List[dict] = []
        for node in (der_parse(entries.data, entries.content_start,
                               entries.start + entries.total_len) if entries else []):
            if node.tag != 0xBF2F:
                continue
            fields = tlv.to_dict(node.content)
            out.append({
                "seq": int.from_bytes(fields.get(0x80, b"\x00"), "big"),
                "operation": self._pmo_name(fields.get(0x81, b"")),
                "address": fields.get(0x0C, b"").decode("utf-8", "replace"),
                "iccid": tlv.bcd(fields.get(0x5A, b""), swap=True),
                "raw": node.content.hex(),
            })
        return out

    async def retrieve_notification(self, seq: int) -> Optional[bytes]:
        raw = seq.to_bytes(max(1, (seq.bit_length() + 7) // 8), "big")
        rsp = await self.es10(_tlv(0xBF2B, _tlv(0xA0, _tlv(0x80, raw))),
                             "RetrieveNotificationsList")
        root = der_find(rsp, 0xBF2B)
        if root is None:
            return None
        entry = der_find_in(root, 0xA0)
        return entry.content if entry else None

    async def remove_notification(self, seq: int) -> None:
        raw = seq.to_bytes(max(1, (seq.bit_length() + 7) // 8), "big")
        await self.es10(_tlv(0xBF30, _tlv(0x80, raw)), "NotificationSent")


# --------------------------------------------------------------------------- #
# device identity helpers (only needed for the optional IMEI field)
# --------------------------------------------------------------------------- #
def _gsm_bcd(digits: str) -> bytes:
    """GSM 03.40 style BCD: nibbles swapped per byte ("12326129" -> 21 32 16 92)."""
    if len(digits) % 2:
        digits += "F"
    raw = bytes.fromhex(digits)
    return bytes(((b & 0x0F) << 4) | (b >> 4) for b in raw)


def _tac(imei: str) -> bytes:
    digits = "".join(ch for ch in imei if ch.isdigit())
    return _gsm_bcd(digits[:8].ljust(8, "0"))


def _imei_bcd(imei: str) -> bytes:
    digits = "".join(ch for ch in imei if ch.isdigit())
    return _gsm_bcd(digits[:16].ljust(16, "0"))


# --------------------------------------------------------------------------- #
# results and segmentation
# --------------------------------------------------------------------------- #
def parse_installation_result(rsp: bytes) -> dict:
    """Parse the ProfileInstallationResult (BF37) returned by the last segment."""
    out: Dict[str, object] = {}
    root = der_find(rsp, 0xBF37)
    if root is None:
        out["raw"] = rsp.hex()
        return out
    data = der_find_in(root, 0xBF27)
    if data is None:
        return out
    meta = der_find_in(data, 0xBF2F)
    if meta is not None:
        iccid = der_find_in(meta, 0x5A)
        if iccid is not None:
            out["iccid"] = tlv.bcd(iccid.content)
        seq = der_find_in(meta, 0x80)
        if seq is not None:
            out["seq"] = int.from_bytes(seq.content, "big")
    final = der_find_in(data, 0xA2)
    if final is not None:
        children = der_parse(final.content)
        if children:
            out["status"] = "success" if children[0].tag == 0xA0 else "error"
            out["detail"] = {hex(c.tag): c.content.hex()
                             for c in der_parse(children[0].content)}
    return out


def segment_bpp(bpp: bytes) -> List[Tuple[bytes, str]]:
    """Split a bound profile package into LoadBoundProfilePackage segments.

    SGP.22 2.5.5: the BPP header plus initialiseSecureChannelRequest in the
    first segment, then configureISDP, the storeMetadata header and its
    children, replaceSessionKeys, and the loadProfileElements header plus one
    command per profile element (the split the reference LPA ``lpac`` uses,
    which keeps every STORE DATA block small).
    """
    root = der_find(bpp, 0xBF36)
    if root is None:
        raise BlpaError("bound profile package has no BF36 tag")

    def seg(start: int, length: int) -> bytes:
        return bpp[start:start + length]

    fragments: List[Tuple[bytes, str]] = []
    bf23 = der_find_in(root, 0xBF23)
    if bf23 is None:
        raise BlpaError("BPP has no BF23 (initialiseSecureChannel)")
    fragments.append((seg(root.start, (bf23.start - root.start) + bf23.total_len),
                      "initialiseSecureChannel"))

    a0 = der_find_in(root, 0xA0)
    if a0 is not None:
        fragments.append((seg(a0.start, a0.total_len), "configureISDP"))

    a1 = der_find_in(root, 0xA1)
    if a1 is None:
        raise BlpaError("BPP has no A1 (storeMetadata)")
    fragments.append((seg(a1.start, a1.header_len), "storeMetadata header"))
    for child in der_parse(a1.data, a1.content_start, a1.start + a1.total_len):
        fragments.append((seg(child.start, child.total_len), "storeMetadata"))

    a2 = der_find_in(root, 0xA2)
    if a2 is not None:
        fragments.append((seg(a2.start, a2.total_len), "replaceSessionKeys"))

    a3 = der_find_in(root, 0xA3)
    if a3 is None:
        raise BlpaError("BPP has no A3 (loadProfileElements)")
    fragments.append((seg(a3.start, a3.header_len), "loadProfileElements header"))
    for child in der_parse(a3.data, a3.content_start, a3.start + a3.total_len):
        fragments.append((seg(child.start, child.total_len), "loadProfileElements"))
    return fragments


# --------------------------------------------------------------------------- #
# high level flow
# --------------------------------------------------------------------------- #
async def download_profile(card: Card, activation_code: str,
                           confirmation_code: Optional[str] = None,
                           imei: str = "", enable: bool = False,
                           on_step=None) -> dict:
    """Run the whole SGP.22 download against the SM-DP+ of the activation code.

    ``card`` must be connected; only ``store_data`` is used, so this works with
    the Linklan, 9eSIM and BeeSIM backends alike.
    """
    code = parse_activation_code(activation_code)
    log.info("activation code: smdp=%s matchingId=%s", code.smdp, code.matching_id)
    smdp = Smdp(code.smdp)
    euicc = Euicc(card)

    info1 = await euicc.info1()
    challenge = await euicc.challenge()
    log.info("EuiccInfo1 %d bytes, challenge %s", len(info1), challenge.hex())

    auth = smdp.initiate_authentication(challenge, info1, code.matching_id)
    transaction_id = auth.get("transactionId") or ""
    log.info("transactionId %s", transaction_id)

    auth_rsp = await euicc.authenticate_server(
        base64.b64decode(_clean_b64(auth["serverSigned1"])),
        base64.b64decode(_clean_b64(auth["serverSignature1"])),
        base64.b64decode(_clean_b64(auth["euiccCiPKIdToBeUsed"])),
        base64.b64decode(_clean_b64(auth["serverCertificate"])),
        code.matching_id, imei=imei)

    client = smdp.authenticate_client(transaction_id, auth_rsp)
    prepare_rsp = await euicc.prepare_download(
        base64.b64decode(_clean_b64(client["smdpSigned2"])),
        base64.b64decode(_clean_b64(client["smdpSignature2"])),
        base64.b64decode(_clean_b64(client["smdpCertificate"])),
        confirmation_code)
    bpp = smdp.get_bound_profile_package(transaction_id, prepare_rsp)
    log.info("bound profile package: %d bytes", len(bpp))

    install_raw = await euicc.load_bpp(bpp, on_step=on_step)
    result = parse_installation_result(install_raw) if install_raw else {}
    result.setdefault("status", "unknown")

    # notifications: tell the SM-DP+ that the profile was installed
    try:
        for note in await euicc.list_notifications():
            seq = note.get("seq")
            if seq is None:
                continue
            pending = await euicc.retrieve_notification(seq)
            if pending:
                smdp.handle_notification(pending, transaction_id)
            await euicc.remove_notification(seq)
    except (BlpaError, SmdpError) as exc:
        log.warning("notification handling failed: %s", exc)

    iccid = result.get("iccid", "")
    if enable and iccid:
        card_profile = next((p for p in await card.profiles() if p.iccid == iccid), None)
        if card_profile is not None:
            await card.enable(iccid)
            result["enabled"] = True

    result["matching_id"] = code.matching_id
    result["smdp"] = code.smdp
    result["transaction_id"] = transaction_id
    return result


# --------------------------------------------------------------------------- #
# offline self test
# --------------------------------------------------------------------------- #
def _synthetic_bpp() -> bytes:
    """A structurally valid (but not cryptographically signed) BPP."""
    init = _tlv(0xBF23, _tlv(0x30, _tlv(0x80, b"\x01\x02\x03\x04")
                             + _tlv(0x5F37, b"\x11" * 8)))
    conf = _tlv(0xA0, _tlv(0x30, _tlv(0x80, b"\x01")))
    meta = _tlv(0xA1, _tlv(0x30, _tlv(0x80, b"\x01")
                           + _tlv(0x5A, bytes.fromhex("8944012345678901234F")))
                + _tlv(0x30, _tlv(0x80, b"\x02")))
    keys = _tlv(0xA2, _tlv(0x30, b"\x00" * 8))
    elements = _tlv(0xA3, b"".join(_tlv(0x86, bytes([i]) * 32) for i in range(1, 6)))
    return _tlv(0xBF36, init + conf + meta + keys + elements)


def dry_run_download(activation_code: str, max_block: int = 240) -> dict:
    """Offline self-test of the machinery: no card, no network."""
    code = parse_activation_code(activation_code)
    bpp = _synthetic_bpp()
    fragments = segment_bpp(bpp)
    too_big = [label for frag, label in fragments if len(frag) > max_block]
    return {
        "smdp": code.smdp,
        "matching_id": code.matching_id,
        "bpp_bytes": len(bpp),
        "segments": [{"label": label, "bytes": len(frag)} for frag, label in fragments],
        "segments_over_block_limit": too_big,
        "block_limit": max_block,
        "note": "structural check only: no card, no SM-DP+, nothing installed",
    }
