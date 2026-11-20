# `src/web` — WebBLE console for all three cards

A single page that talks to any of the three card families over **Web
Bluetooth**, no backend, no extension.

```
index.html      UI: choose a card (kind auto-detected from its name), connect,
                info/eid/profiles, enable/disable/delete, credentials shown per family
transports.js   the three transports (Linklan, 9eSIM, BeeSIM) + tiny protobuf codec
tlv.js          BER-TLV + SGP.22 command builders (shared by all three)
crypto.js       HMAC-SHA256 (WebCrypto), AES-CCM (built on WebCrypto AES-CBC/CTR),
                pure-JS 3DES-ECB
vectors.json    known-good crypto vectors (generated from the Python client)
test.mjs        `node test.mjs` — validates the crypto + TLV against those vectors
test-linklan-mock.mjs  `node test-linklan-mock.mjs` — drives LinklanCard against a
                mock GATT server that emulates the card firmware (handshake, AES-CCM,
                SCARD bridge, ES10), so the browser transport is testable without a browser
```

## Run

```bash
cd src/web
python3 -m http.server 8000        # http://localhost is a secure context
# open http://localhost:8000 and use Chrome or Edge
```

## Choosing a card

There is no card-type drop-down: **Choose card…** opens the browser's picker,
which is filtered to the three families, and the kind is derived from the name
(`BeeSIM*` → beeesim, `9eSIM*`/`esim_writer*` → 9esim, `*BLE-eSIM*` → linklan).
Chrome also lets the page list devices it was already granted access to
(`navigator.bluetooth.getDevices()`), so a previously used card can be re-selected
without the picker.

Both cards with a key keep their credential per card in `localStorage`
(`blpa:creds:<device id>`), so a reload — or a re-keyed card — needs no retyping.
Only Linklan's is *required*; 9eSIM's is optional and falls back to the
name-derived default.  A successful *Rekey* also stores the password it just set,
so reconnecting after the rename works without retyping it.

| detected | credential | storage |
|---|---|---|
| **Linklan** | password (= the EID's last six digits) and/or PSK hex | remembered per device id; **Forget** removes it |
| **9eSIM** | optional, **prefilled** with the name-derived default (reversed last six characters) | a password that differs from that default is **remembered per card**; the derivable default itself is not stored. The page can also **change** the password (see below) |
| **BeeSIM** | none — the card has no authentication | not stored |

Nothing secret is ever stored for a card that does not need it.

## Publishing

This directory is the published artefact.  `.github/workflows/publish-web.yml`
pushes it to the `web` branch on every change under `src/web` (after running both
test suites), so GitHub Pages serves `blpa.cyyself.name` straight from it.
`CNAME` and `.nojekyll` ship along; tests, vectors and this README do not.

## Supported

| card | what works | notes |
|---|---|---|
| **Linklan** | ✅ verified in Chrome: connect, EID, profile list, enable/disable/delete | needs the PSK or the card password (the EID's last six digits) |
| **9eSIM** | EID, profile list, enable/disable/delete | password defaults to the reversed last six characters of the BLE name |
| **BeeSIM** | EID, profile list, enable/disable/delete | no authentication layer; protocol verified on hardware, browser path not yet exercised |

## Three browser-only traps (all fixed, all test-pinned)

1. **The reply is a bare `SecurityData`.** The card answers an encrypted request
   with `{ 1: id, 2: ciphertext }` and the AUTH with a bare `{ 3: SecurityProtocol }`
   — *not* nested inside `{ cmd = 3, request = … }`. Parsing only the nested shape
   makes every reply look like garbage.  (A bare `SecurityData` with `id = 3` is
   byte-identical to a nested envelope, so try nested first, then fall back.)
2. **The AUTH frame needs the extra wrapper:**
   `SecurityData{ 1: id, 3: SecurityProtocol{ 2: SecurityAuth{ 1: random, 2: proof } } }`.
   Without the `SecurityProtocol` level the card reads the random as the type and
   the handshake is rejected as "wrong PSK/password".
3. **Web Bluetooth has no MTU API**, and Chrome throws on writes above ATT MTU−3.
   Writes start at 244 bytes, fall back to without-response, and halve down to 20.

Both suites pin the wire format: `test.mjs` asserts the exact AUTH frame from the
working Python client (`0803 123a 0800 1a36 1234 0a10 …`, 62 bytes) and classifies
captured hardware replies; `test-linklan-mock.mjs` runs a whole session against a
mock peripheral that speaks the real dialect.

## Changing a 9eSIM's name and password

When a 9eSIM is connected the page shows a **Rekey** panel (prefilled with the
current suffix and its derived password).  It sends the vendor command

```
30 27 00 00 09 | 11 11 11 | <new 6-hex suffix, 3B> | <passwordHex, 3B>      (0x80 fallback)
```

— verified on hardware, including the round trip back to the original identity.
Because the 3DES key is derived from name + password, **the card renames itself**:
after a rekey you disconnect and choose the card again under its new name (the
page keeps nothing for 9eSIM, so there is no stale credential to clear).

## Browser reality check

* Chrome/Edge on desktop and Android.  **Safari has no Web Bluetooth**, so on
  iOS/iPadOS use [Bluefy — Web BLE Browser](https://apps.apple.com/us/app/bluefy-web-ble-browser/id1492822055),
  which implements the Web Bluetooth API; the page detects the missing API and
  points there.  Firefox only has it behind flags.
* The page must be served from `https://` or `http://localhost`.
* `navigator.bluetooth.requestDevice()` needs a user gesture (the Connect button).
* Web Bluetooth exposes **no MTU control**. The Linklan transport therefore
  writes fixed 244-byte chunks; the card reassembles by its 2-byte length
  prefix, so this is expected to work, but it is the one thing that has only
  been proven at 512-byte chunks from Python.
* A card accepts a single central: close the phone app and any Python client
  before connecting from the browser.

## What is verified

`test.mjs` compares the JavaScript against the *Python* implementation:

```
node test.mjs                            # 11/11
aesccm    OK    AES-CCM(12-byte nonce, 4-byte tag) matches the Python AESCCM()
aesccm D  OK    decrypt round-trip (and tag rejection)
3des      OK    2-key 3DES ECB matches Cryptography's TripleDES
3des D    OK    round-trip
tlv       OK    parse of a synthesised BF2D profile list (demo ICCID)
cmdEnable OK    BF31 { A0 { 5A … } 81 … } == bf3111a00f5a0a9800000000000000000f28101ff
9esim key OK    authKey("DEMO123456") == 56654321566543215665432100000000
resultCode OK   BF31 03 80 01 00 -> 0
authframe OK    AUTH frame == 0803 123a 0800 1a36 1234 0a10 <16B> 1220 <32B> (62 bytes)
rekey     OK    30 27 00 00 09 111111 250401 654321   (hardware-verified bytes)
classify  OK    envelope shapes: DeviceRsp challenge, bare {3: SecurityProtocol},
                bare SecurityData (also with id = 3), DeviceInfo, {5: error}
```

`node test-linklan-mock.mjs` goes further: it runs the whole `LinklanCard`
against a mock GATT peripheral that speaks the documented dialect (challenge →
AUTH → AES-CCM session → SCARD bridge → ES10), and checks handshake, EID,
profile list and an enable.  What it cannot cover is the browser's own GATT
implementation and MTU behaviour — for that the page has to run with the card
nearby.
