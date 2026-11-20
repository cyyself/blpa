# Protocol documents

One document per card, plus the differences between them:

* [`linklan.md`](linklan.md) — Linksfield / Linklan `BLE-eSIM` (LPAd protobuf, PSK + AES-CCM, SCARD bridge)
* [`nble.md`](nble.md) — 9eSIM / NBLE-SIM writers (3DES challenge, framed APDUs)
* [`beeesim.md`](beeesim.md) — BeeSIM readers (grouped APDUs over `0xAE30`, no auth)
* [`download.md`](download.md) — profile download (SGP.22): ES10b legs, ES9+ flow, segmentation

## The three cards side by side

| | **Linklan / Linksfield** | **9eSIM (NBLE)** | **BeeSIM** |
|---|---|---|---|
| advertised name | `BLE-eSIM-*` | `9eSIM*` (`esim_writer` = legacy JSON fw) | `BeeSIM*` |
| GATT | NUS `6e400001…` | NUS `6e400001…` | `0000ae30-…` |
| framing | 2-byte BE length + protobuf | header byte + `counter‖apdu‖sum16`, 18-byte-ish chunks | `[total, index]` + 18 bytes |
| transport auth | **PSK** handshake, AES-CCM session | **password → 3DES** challenge/response | **none** |
| key material | `HMAC_SHA256(password, "SecurePbChannel")`, password = EID tail | `(last2(name) + reverse(last6(name)))×3 + 0` → 3DES key | – |
| APDU path | SCARD bridge (protobuf `transmitApdu`), logical channel 4 | raw APDU frames, basic channel | raw APDU frames, logical channel 1 |
| STORE DATA | `80 E2 91 00`, ≤240 | `80 E2`, ≤239 | `81 E2`, ≤239 |
| profile wrapper | **needs `A0`** | accepted (we send it) | accepted |
| raw APDU exposure | only via the bridge | yes | yes |
| verified here | yes | yes | yes |
| unique quirks | `EuiccCardReq` unsupported, link drops on >255-byte APDUs, `91xx` after switch | basic-channel only, Le ≤ 0x4F, 5 s auth penalty (Linklan) / immediate (9eSIM) | vendor `A0 3E` TX power, `A0 3F` reset |

## What is common

All three end up speaking the same GSMA ES10 command set over ISO-7816, so the
TLV builders in `blpa/tlv.py` are shared:

```
EID       BF3E { 5C 01 5A }
profiles  BF2D { 5C <tags> }
enable    BF31 { A0 { 5A <iccid> , 81 <refresh> } }
disable   BF32 { A0 { 5A <iccid> } }
delete    BF33 { A0 { 5A <iccid> } }
nickname  BF29 { 5A <iccid>, 90 <utf8> }
notify    BF28 / BF2B / BF30
```

Only the *transport* differs — which is exactly why `blpa` keeps three small
backends behind one `Card` interface.
