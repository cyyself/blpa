# Profile download (SGP.22)

All three cards expose the same card-side interface for a download: ES10b
commands sent as **STORE DATA** (`CLA=0x80|channel, INS=E2, P1=11/91`) over the
ISD-R applet.  The SM-DP+ side is a plain HTTPS REST API (ES9+).  So one
implementation drives every card — `src/py/blpa/sgp22.py`, used by
`blpa download <activation-code>`.

| card | ES10b over STORE DATA | full download verified |
|---|---|---|
| Linklan / Linksfield | SCARD bridge, protobuf `transmitApdu` | **yes** — real profiles installed (sibling `Linklan` project) |
| 9eSIM (NBLE) | `CLA 0x80`, 239-byte blocks, chained `11…91` | ES10b legs verified (challenge, EuiccInfo1/2) |
| BeeSIM | `CLA = channel\|0x80`, chained blocks, `61xx` fetch | ES10b legs verified (challenge, EuiccInfo1/2) |

`blpa download --dry-run 'LPA:1$…'` checks the activation code and the package
segmentation offline (no card, no network).

## 1. Where each piece runs

```
        activation code                     ES9+ (HTTPS/JSON)            ES10b (STORE DATA)
  LPA:1$<smdp>$<matchingId>  ──┐
                               ├─ GetEUICCChallenge (BF2E) ──────────────► card
                               ├─ GetEuiccInfo1     (BF20) ──────────────► card
                               ├─ initiateAuthentication ──► SM-DP+
                               ├─ AuthenticateServer (BF38) ─────────────► card
                               ├─ authenticateClient     ──► SM-DP+
                               ├─ PrepareDownload    (BF21) ─────────────► card
                               ├─ getBoundProfilePackage ──► SM-DP+
                               ├─ LoadBoundProfilePackage    ────────────► card
                               └─ handleNotification + NotificationSent (BF30)
```

The card never talks to the network: it only answers ES10b.  Everything the
SM-DP+ needs to authenticate the eUICC travels through the phone.

## 2. Activation code

```
LPA:1$<smdp-address>$<matchingId>[$<oid>]        "LPA:" prefix optional
```

`matchingId` is the download token (also called *activation code* in the narrow
sense).  It is a bearer secret: whoever knows it can pull the profile onto their
own eUICC, so it is single-use and usually bound to a purchased order.

## 3. ES10b transcripts (verified on hardware)

Challenge — `BF2E00`, answer `BF2E{ 80: 16-byte random }`:

```
9eSIM    -> bf2e1280103f86426d0387f176e820fe9435a1c30f
BeeSIM   -> bf2e128010605a2cc12b2293ee0726a1a9cb9cb81b
```

`EuiccInfo1` — `BF2000`, answer `BF20` (some firmwares answer `BF3C` with the
same content; `sgp22.py` re-tags it as `BF20`, which is what the SM-DP+ wants):

```
9eSIM    -> bf2035 8203020200 a916041481370f5125d0b1d408d4c3b232e6d25e795bebfb
                     a916041481370f5125d0b1d408d4c3b232e6d25e795bebfb        (56 B)
BeeSIM   -> bf2035 8203020202 a9160414… (same shape, different svn)         (56 B)
```

`EuiccInfo2` — `BF2200` gives `BF22{ 81: svn, 82: …, 83: … , 84: {81: …} }`
(126–128 bytes on these cards); it is not needed for a download.

Note the two bytes `8203 0202 00`: `EuiccInfo1.versionSupported` etc. are tiny —
these are minimal eUICCs, which is why a download needs nothing else from them.

## 4. AuthenticateServer: the payload and the IMEI trap

`BF38` carries five concatenated fields:

```
BF38 {
  30   serverSigned1                        (ASN.1 DER, from the SM-DP+)
  5F37 serverSignature1                     (1-bit signature)
  04   euiccCiPKIdToBeUsed                  (PKI id the SM-DP+ chose)
  30   serverCertificate                    (SM-DP+ certificate + chain)
  A0   ctxParamsForCommonAuthentication {
         80 matchingId (UTF8String)
         A1 deviceInfo {
            80 tac (GSM 03.40 BCD, 4 bytes)
            A1 deviceCapabilities (empty BIT STRING is fine)
            82 imei (BCD, 8 bytes)  OPTIONAL
         }
      }
}
```

`SGP.22 §5.7.13`: `DeviceInfo.tac` and `deviceCapabilities` are mandatory, `imei`
is optional — and it is a **sibling** of `deviceCapabilities`, not a child.  With
AUTOMATIC TAGS that means `80`/`A1`/`82` at the same level.  Nesting the IMEI
inside the capabilities block (or omitting `deviceInfo` entirely) makes the card
reject the command — on the Linklan card that surfaced later as
`authenticateClient … 1.6/2.1 Invalid`.

A real SM-DP+ reply produced a **802-byte** `BF38` for these cards, i.e. four
STORE DATA blocks with `P1=0x11` on the first three and `P1=0x91` on the last.

## 5. PrepareDownload and the confirmation code

`BF21 { 30 smdpSigned2, 5F37 smdpSignature2, [04 confirmationCodeHash,] 30 smdpCertificate }`

The confirmation code (SGP.22 §5.7.5) is hashed as
`SHA256(SHA256(code) ‖ transactionId)` and inserted as an OCTET STRING before the
certificate.  Without a confirmation code the field is simply absent.

## 6. LoadBoundProfilePackage segmentation

SGP.22 §2.5.5 requires the bound profile package (`BF36`) to be loaded in the
same pieces the reference LPA (`lpac`) uses — the card's STORE DATA buffer is far
smaller than the package (tens of KB):

| # | segment | content |
|---|---|---|
| 1 | `initialiseSecureChannel` | `BF36` header + `BF23` |
| 2 | `configureISDP` | `A0` (optional) |
| 3 | `storeMetadata header` | `A1` tag+length only |
| 4…n | `storeMetadata` | each child of `A1`, one segment per element |
| n+1 | `replaceSessionKeys` | `A2` (optional) |
| n+2 | `loadProfileElements header` | `A3` tag+length only |
| n+3… | `loadProfileElements` | one profile element per segment |

The segments are **slices of the original buffer** (the `BF36` header is repeated
only in the first one), so the offsets come from a DER parser that records
absolute positions (`sgp22.der_parse`).  A synthetic package in the test yields
12 segments; real packages are dominated by the `loadProfileElements` slices.

## 7. ProfileInstallationResult

The last segment's response contains `BF37`:

```
BF37 { BF27 {
          BF2F { 80: seqNumber, 5A: iccid, … }        (notification metadata)
          A2 { A0 { … } }   success          /  A2 { A1 { … } }  error
       } }
```

`sgp22.parse_installation_result()` returns `{status, iccid, seq, detail}` and the
CLI prints it as JSON.

## 8. Notifications

```
BF28 (ListNotification)               -> BF28 { A0 { BF2F { 80: seq, 81: PMO, 5A: iccid, 0C: address } } }
BF2B (RetrieveNotificationsList)      -> BF2B { A0 { <PendingNotification TLV> } }
BF30 (NotificationSent)  { 80: seq }
```

`profileManagementOperation` is a BIT STRING: `0780` install, `0640` enable,
`0520` disable.  The retrieved bytes go to the SM-DP+ as
`handleNotification { pendingNotification }`, which succeeds with **HTTP 204 and
an empty body** (SGP.22 §6.3) — treat any JSON-parsing of that reply as a bug.
Notifications are sent **after** the profile is installed; skipping them leaves
the order in `installed` state on the server, so `sgp22.download_profile()`
drains the whole list.

## 9. Per-card transport details

| | Linklan | 9eSIM | BeeSIM |
|---|---|---|---|
| STORE DATA CLA | `0x80` (bridge, protobuf) | `0x80` | `0x80 \| channel` |
| block size | up to 240 B | 239 B | 239 B |
| chaining | `P1=11` … `P1=91` | same | same |
| `61xx` | follow with `80 C0` | `80\|0 C0` | `C0` on the same CLA |
| quirks | `SW 6881` = channel gone → reopen channel 4 and retry the block | password → 3DES handshake first | no MANAGE CHANNEL; SELECT with `CLA=channel`; the `61xx` body must keep its status word (`_get_response` returns it, `store_data` strips it) |

## 10. Diagnostics

| symptom | meaning |
|---|---|
| `SW 6982` on `BF38` | the card does not accept the server certificate / PKI id — the eUICC's trusted CI list and the SM-DP+'s chain disagree. Seen with a bogus `matchingId` whose profile does not exist: the SM-DP+ still answers, but the chain is not the one the card trusts |
| `SW 6A80` / `6A81` | malformed command: wrong nesting in `ctxParams` (see §4), or a bad block sequence |
| `SW 6881` (Linklan) | logical channel leaked by an earlier session — `linklan.store_data` reopens and retries |
| `GetEuiccInfo1` answers `BF3C` | old firmware; re-tag the content as `BF20` |
| SM-DP+ `functionExecutionStatus: Failed` | the `matchingId` is unknown/expired, or the order is not released yet |

## 11. Security notes

* The TLS chain of an SM-DP+ is issued by the **GSMA CI**, not by a public web
  CA, so a GSMA root bundle ships with the toolkit (`sgp22.certs/`).  Validating
  against the system store alone fails on every SM-DP+.
* The activation code is the only secret in the flow; it is not derived from the
  card, so intercepting it (or the BLE session that carried it) is enough to
  steal a profile.  This is why the Linklan transport weakness matters: a sniffed
  handshake yields the PSK, and a captured session may carry the activation code
  or the downloaded package.
* The SM-DP+ learns the EID (and the IMEI if `deviceInfo` carries one), so a
  download links the card identity to the purchase.  `blpa` sends the IMEI only
  when the card reports one or `--imei` is given.
* `LoadBoundProfilePackage` traffic is already bound/encrypted by the SM-DP+ per
  eUICC, so the transport does not need to hide it — but a replayed package
  cannot be installed twice.
