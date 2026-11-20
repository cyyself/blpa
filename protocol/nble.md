# 9eSIM / NBLE-SIM writer (`nble`) — protocol

> **Status** verified on hardware (EID `89086029…`); full identifiers and the
> card password are withheld.
> **Implementation** `src/py/blpa/nble.py` (`NbleCard`), `src/web/transports.js` (`Esim9Card`)
> **Reference** NekokoLPA2 `NBLESimAdapter` (MIT)

## 0. Which 9eSIM are you holding?

| firmware | advertised name | protocol |
|---|---|---|
| legacy | `esim_writer…` | JSON over Nordic UART (`{"cmd":"APDU","action":1,"data":"<hex>"}`, base64-wrapped writes) — NekokoLPA1 `SimLinkDevice.ts` |
| current | `9eSIM…` (e.g. `DEMO123456`) | **the framed, 3DES-authenticated protocol below** |

## 1. Link layer

| item | value |
|---|---|
| service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` (Nordic UART) |
| host → card | `6e400002-…`, **write without response** |
| card → host | `6e400003-…`, notify |
| MTU | 256 on the card used; the host chooses its chunk size (we use 100) |

## 2. Password and key

```
password = reverse(last 6 characters of the device name)      # "DEMO123456" -> "654321"
if those 6 characters are not all hex:
    password = CRC24(original string) as six uppercase hex digits

authKey  = hex( (last2(name) + password) × 3 + "00000000" )    # 16 bytes, 2-key 3DES
# "DEMO123456": last2 = "56", base = "56654321"
# authKey = 00 00 40 52 00 00 40 52 00 00 40 52 00 00 00 00
```

The password is derived from the **broadcast name**, so this is obfuscation, not
authentication.

## 3. Handshake (immediately after connecting)

```
card → host  0xE0 ‖ enc(16)              # single 17-byte packet
host          plain = 3DES_DECRYPT(enc)  # ECB, authKey
              counter = plain[7] | plain[8] << 8          # 16-bit LE
              counter = (counter + 1) & 0xFFFF
              plain[7..8] = counter (LE)
host → card  0xE0 ‖ 3DES_ENCRYPT(plain)  # single 17-byte write, not re-framed
card → host  0xE0 90 00   ok
             0xE0 6A 86   wrong password
```

## 4. APDU transport

```
body  = counter(1B, wraps at 256) ‖ apdu
frame = body ‖ sum16(body)               # sum16 = big-endian sum of all bytes
```

`frame` is split into `(write_size − 1)` byte chunks; each packet is
`header ‖ chunk`:

```
header = (last ? 0x20 : 0x00) | (sequence & 0x1F)      sequence starts at 0
```

Replies use the same layout: concatenate `packet[1:]`, verify
`sum16(payload[:-2]) == payload[-2:]`, then `counter = payload[0]`,
`apdu = payload[1:]`.

## 5. Channel and ES10

The eUICC is on the **basic channel** — no MANAGE CHANNEL needed:

```
SELECT ISD-R  00 A4 04 00 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00
ES10          80 E2 <p1> <block> <lc> <data>        p1 0x11 more / 0x91 last, lc ≤ 239
GET RESPONSE  80 C0 00 00 <le>                      (some firmware caps Le at 0x4F)
```

| operation | request |
|---|---|
| GetEID | `BF3E 03 5C 01 5A` |
| GetProfilesInfo | `BF2D 0B 5C 09 5A 90 91 92 B7 9F70 95 99` |
| EnableProfile | `BF31 { A0 { 5A <iccid>, 81 FF } }` |
| DisableProfile / DeleteProfile / SetNickname | `BF32` / `BF33` / `BF29` (same TLV shapes as SGP.22) |
| Notifications | `BF28 00`, `BF2B { A0 { 80 <seq> } }`, `BF30 { 80 <seq> }` |

The card used for verification had **no profiles installed**, so it answers
`BF2D 02 A0 00`; profile operations are implemented but unexercised on hardware.

## 6. Verified transcript

```
→ hello … card sends E0 1c 97 8f … (16 encrypted bytes)
  plain = 3DES⁻¹: … counter 19095 → 19096 …
→ E0 <3DES(plain)>
← E0 90 00
→ [counter 00] 00 A4 04 00 10 A0 … 00  (SELECT ISD-R)
                  ← 6F 1F 84 10 … 90 00
→ [01] 80 E2 91 00 06 BF 3E 03 5C 01 5A
                  ← BF 3E 12 5A 10 89 08 60 29 … (EID, prefix shown)  90 00
```

## 7. Changing the name and password (re-keying)

The writer accepts a vendor command that sets the **BLE name suffix and the
password together** — that is how the official app's "update device" dialog
works.  Taken from NekokoLPA2 (`_performUpdate`, `nble_sim_adapter.dart`) and
**verified on hardware** with a full round trip (see the transcript below):

```
CLA  30            (falls back to 80 if the card answers 6E00)
INS  27
P1   00   P2 00
Lc   09
data 11 11 11 | <new 6-hex-character name suffix, 3 bytes> | <passwordHex, 3 bytes>
```

Both halves must be six **hex** characters, i.e. three bytes each:

* only the **3-byte suffix** is editable — the `9eSIM` prefix is fixed by the
  firmware, the advertised name is `9eSIM` + suffix (`9eSIM250400` →
  `9eSIM250401` after a rekey with suffix `250401`);
* `passwordHex` is the password as six hex digits; a non-hex password string is
  first reduced with the CRC24 of §2, so it always fits.

The card renames itself, so after the command the host must reconnect using the
new name **and** the new password — the PSK/3DES key is derived from exactly those
two values (`last2(name) + passwordHex`).  `blpa` exposes this as:

```bash
python -m blpa --card 9esim rekey 250401 654321 --yes     # rename + new password
python -m blpa --card 9esim rekey 250400 004052 --yes     # back to the default
```

Verified round trip on a real card (EID `89086029…`, unchanged throughout):

```
baseline    name=9eSIM250400  pw 004052   -> ok
rekey       30 27 00 00 09 111111 250401 654321 -> 9000
reconnect   name=9eSIM250401  pw 654321   -> ok, same EID
rekey back  30 27 00 00 09 111111 250400 004052 -> 9000
reconnect   name=9eSIM250400  pw 004052   -> ok, same EID
```

Two practical notes from that run: the card re-advertises under the new name
within a few seconds, and the *name-derived default* password follows the name
(`9eSIM250401` → `104052`), so after a custom password is set the host must keep
passing it explicitly (the CLI's `--password` / `ESIM9_PASSWORD`).

## 8. Security notes

* Password, key and the challenge all derive from public or low-entropy material
  (the BLE name is broadcast in every advertising packet).
* **Two attack surfaces, with very different costs.**
  *Online* (talking to the card) is slow: the card sends a random 16-byte challenge
  and expects `3DES(key)` of it back, and a session allows a single attempt.
  Measured on hardware:

  ```
  wrong key on a fresh connection -> E0 6A86          2.15 s per full cycle
  second attempt on the same link -> no reply         one guess per connection
  4 consecutive failures          -> card still fine, password unchanged
  ```

  *Offline* (recording someone else's handshake) is cheap: the link layer is not
  encrypted, so a sniffer captures `C1 = 3DESₖ(challenge)` and the client's
  `C2 = 3DESₖ(challenge′)`, where `challenge′` is the same block with the 16-bit
  counter at bytes 7–8 incremented.  For a candidate key `K` that is a complete
  verifier: `D_K(C1)`, bump bytes 7–8, re-encrypt, compare with `C2`.  Measured on
  the captured pair from this card: **135 000 candidates/s on one CPU core**, i.e.
  the whole 2^24 space in ≈ **2 minutes** (seconds on a GPU); a wrong candidate
  never matches, so the search is unambiguous.

  The stored password form is always **3 bytes** (six hex characters, or the CRC24
  of an arbitrary string), i.e. a 2^24 space; a plain 6-digit PIN is 10^6.  Online
  that is ≈ **25 days** for six digits and ≈ **418 days** for the whole space (per
  card and adapter), with no lockout — but the default password is derived from the
  advertised name anyway (§2), and the offline route makes the space irrelevant
  once a legitimate session has been sniffed.
* After the handshake the APDUs are sent **in plaintext** inside the framed
  protocol — the 3DES protects only the handshake, so a sniffer reads EID,
  profile list and every profile operation without cracking anything.
* Defence: re-key the card (`rekey`, §7) so the password no longer follows the
  name.
* Once authenticated the card grants full profile management (enable/disable/
  delete/rename) with no further checks.
