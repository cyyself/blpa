# Linklan / Linksfield BLE-eSIM — protocol

> **Status** verified on hardware (EID `89044045…`); the full EID, ICCIDs, card
> name and password are withheld — the EID's last six digits *are* the password.
> **Implementation** `src/py/blpa/linklan.py`, `src/web/transports.js` (`LinklanCard`)
> **Deep dive** the full byte-level specification — SGP.22 download, vendor-app
> captures, security report — lives in the sibling `Linklan` checkout
> (`docs/protocol.md` there), not in this repository.

## 1. Link layer

| item | value |
|---|---|
| advertised name | `BLE-eSIM-<suffix>` |
| service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` (Nordic UART) |
| host → card | `6e400002-…`, write **with** response |
| card → host | `6e400003-…`, notify |
| framing | `uint16 BE length` ‖ protobuf payload |
| chunking | payload split into writes of `min(512, MTU-3)`; the card reassembles by the length prefix |
| central | exactly one; the card stops advertising while connected |

## 2. Message envelope (protobuf)

```proto
EuiccDeviceReq { int32 cmd = 1; bytes request = 2; }
// cmd: 0 = device, 1 = euicc (vendor card commands, unsupported here), 2 = scard, 3 = security
```

## 3. Credentials — the PSK

```
PSK = HMAC_SHA256(password, "SecurePbChannel")            // 32 bytes

password : the card's "connection password"; the factory default is the
           LAST SIX DIGITS OF THE EID      ("…123456" -> "123456")
SDK fallback : HMAC_SHA256("Linksfield@Esim#2025", "SecurePbChannel")
               = 90fef0652460f33c744912b1350e078c6a3c5a3162c0db84059306b992f70f0c
```

The vendor app resolves the key locally (secure storage → hardcoded default →
a password dialog); it never fetches it from a server.  `blpa` accepts either
`--password` (derives the PSK) or `--psk`/`LINKLAN_PSK` (raw hex).

## 4. Secure channel

```
host → DeviceReq{cmd=1 getDeviceInfo}                       (plaintext)
card → DeviceRsp{…, security = SecurityProtocol{type=AUTH, auth={random = devRandom(16)}}}

mac  = HMAC_SHA256(PSK, "SecurePbChannel", devRandom, cliRandom(16))
auth = HMAC_SHA256(mac[:16], cliRandom, 0*32)

host → EuiccDeviceReq{cmd=3, SecurityData{id = <counter>, sec =
            SecurityProtocol{type=AUTH, auth={random = cliRandom, auth}}}} 
card → EuiccDeviceReq{cmd=3, SecurityData{sec =
            SecurityProtocol{type=UPDATE, config={nonce(12), aad(16), auth(32)}}}}
```

```
session key   = mac[16:32]
encrypted     EuiccDeviceReq{cmd=3, SecurityData{id = ++counter, enc = ct ‖ tag(4)}}
              ct = AES-CCM(key, nonce = config.nonce + counter (last 4B, BE),
                           plaintext = the inner EuiccDeviceReq{cmd, request}, aad = config.aad)
```

Errors: `SecurityData.error = 5` means *counter mismatch or wrong PSK* (the card
waits ~5 s before answering a wrong PSK).  A `SecurityProtocol{AUTH}` arriving
mid-session means the card restarted: re-handshake.

> Framing trap: the ciphertext lives in `SecurityData.enc` (field 2) *inside* the
> envelope's field 2 — not in the envelope itself.

## 5. SCARD bridge (the only working eUICC path)

```proto
SmartCardReq {
  int32 cmd = 1;                    // 1 open, 2 close, 3 transmit
  OpenChannel openChannel = 2;      // {1: aid, 2: p2}
  int32 closeChannel = 3;
  TransmitApdu transmitApdu = 4;    // all sint32 except data
}
TransmitApdu { sint32 channel=1, cla=2, instruction=3, p1=4, p2=5, p3=6; string data=7; }
SmartCardRsp { int32 cmd=1, result=2; OpenChannel openChannel=3; TransmitApduRsp transmitApdu=4; }
TransmitApduRsp { sint32 sw1=1, sw2=2; bytes payload=3; }
```

* AID `A0000005591010FFFFFFFF8900000100` (ISD-R); the firmware always uses
  logical channel **4** and returns the FCI only.
* `result != 0` in `SmartCardRsp` means the bridge failed.
* The native `EuiccCardReq` (cmd = 1) is **not implemented** by this firmware —
  it drops the BLE link.  All eUICC work goes through SCARD/APDUs.

## 6. eUICC / ES10

```
80 E2 91 00 <lc> <data>        STORE DATA; P1 0x11 = more blocks, 0x91 = last,
                               P2 = block number, ≤ 240 bytes per block
61 XX  ->  80 C0 00 00 <le>    GET RESPONSE
```

| operation | request |
|---|---|
| GetEID | `BF3E 03 5C 01 5A` → `BF3E 12 5A 10 89 04 40 45 …` (EID, prefix shown) |
| GetProfilesInfo | `BF2D 0B 5C 09 5A 90 91 92 B7 9F70 95 99` (ICCIDs start `89444765…`) |
| EnableProfile | `BF31 { A0 { 5A <iccid>, 81 FF } }` → `BF31 03 80 01 00`, **SW 91 0B** |
| DisableProfile | `BF32 { A0 { 5A <iccid> } }` |
| DeleteProfile | `BF33 { A0 { 5A <iccid> } }` |
| SetNickname | `BF29 { 5A <iccid>, 90 <utf8> }` |
| ListNotification | `BF28 00` → `BF28 { A0 { BF2F … } }` |

**The `A0` container is mandatory.**  Without it the firmware answers
`BF31 03 80 01 7F` ("undefinedError") for every shape of the request — the single
most expensive discovery in this project.

`SW 91 xx` = "executed, REFRESH requested"; the group also invalidates the
ISD-R channel (expect `6881`/`6985`).  A leaked logical channel from an aborted
session blocks every new one: `SmartCardReq{cmd=1}` then answers a non-zero
`result`, and closing channels 1…5 before re-opening clears it — that recovery is
what makes the CLI reliable after a browser session or a crash.

## 7. BCD rules

| field | encoding |
|---|---|
| ICCID | low-nibble-first (`98 44 74 …` → `8944 74…`, Luhn-valid) |
| EID | high-nibble-first (`89 04 40 …` → `890440…`) |

## 8. ProfileInfo

```
BF2D { A0 { E3 { 5A <iccid>, 9F70 <state 1B>, 91 <name>, 92 <provider>,
               95 <class>, B7 { 80, 81, 82 } } … } }
```

`9F70 = 01` enabled, `00` disabled.  An empty card answers `BF2D 02 A0 00`.

## 9. Verified transcript (profile switch)

```
openChannel(A0000005591010FFFFFFFF8900000100)          -> ch 4
80 E2 91 00 14 BF3111 A00C5A0A<ICCID 10 bytes BCD> 8101FF
   -> SW 91 0B, body BF31 03 80 01 00                   enableResult 0
DeviceReq{resetDevice}                     (applies the REFRESH; the card re-inits)
80 E2 91 00 0E BF2D0B5C095A909192B79F709599  -> BF2D … 9F70 01 …
```

## 10. Security notes

* The PSK is derived from the **EID's last six digits**, i.e. from an identifier
  the vendor prints and the phone displays — effectively no authentication for
  anyone who has seen the card.
* Wrong-PSK attempts cost ~5 s each but there is **no lockout** (0.19 guesses/s,
  no attempt counter), so a 6-digit space is ~60 days online — yet ~1 s offline
  once any valid PSK is known.
* The PSK protects the BLE transport only; profiles stay protected by the eUICC's
  GSMA certificates (chain verified to `GSM Association - RSP2 Root CI1`).
* The **link layer is not encrypted** (no pairing/bonding), and the three values
  needed to check a candidate PSK are all exchanged in clear *before* any key
  exists, so a passive sniffer records them:
  `devRandom` (card, in the plaintext challenge `SecurityProtocol{2{1:devRandom}}`),
  and `cliRandom` + `auth` (client, in the plaintext
  `SecurityProtocol{2{1:cliRandom, 2:auth}}`).  The check is then pure arithmetic —
  for each candidate password `P`:

  ```
  mac  = HMAC_SHA256(HMAC_SHA256(P, "SecurePbChannel"), "SecurePbChannel" ‖ devRandom ‖ cliRandom)
  test = HMAC_SHA256(mac[:16], cliRandom ‖ 0^32)     ==  auth ?
  ```

  Verified against a recorded handshake (captured from the vendor app's logcat,
  same field values a sniffer sees): the proof reproduces exactly, `mac[16:32]` is
  the session key, and a search of the 6-digit password space recovers the
  password in **1.3 s** at ≈309 000 candidates/s on one core — the earlier `~5 s
  per wrong guess` figure applies only to *online* attempts against the card.
  Afterwards the session key is `mac[16:32]`, so every captured AES-CCM frame
  decrypts too: one recorded legitimate session is as good as having the PSK.
  (An attacker needs one *successful* handshake — i.e. someone using the right
  password — but that is exactly what a normal phone connection produces.)
