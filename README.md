# blpa — BLE eSIM toolkit for Linklan, 9eSIM and BeeSIM cards

One small Python package and one Web Bluetooth page that speak to three
different BLE eSIM reader families behind the same operations: **read the EID,
list profiles, enable / disable / delete / rename them, and post the card's
notifications**.  Each card's wire protocol is documented separately in
[`protocol/`](protocol/).

| card | transport | authentication | verified |
|---|---|---|---|
| **Linklan / Linksfield** (`BLE-eSIM-*`) | LPAd protobuf over Nordic UART | PSK handshake + AES-CCM session | ✅ Python **and Chrome (WebBLE)** — EID `89044045…` |
| **9eSIM** (`9eSIM*`, `esim_writer*` = legacy fw) | framed APDUs over Nordic UART | password → 3DES challenge | ✅ Python — EID `89086029…` (browser path untested) |
| **BeeSIM** (`BeeSIM*`) | grouped APDUs over GATT `0xAE30` | none | ✅ Python — EID `89049032…`, profiles, rename |

Protocol documents, one per card:

* [`protocol/linklan.md`](protocol/linklan.md) — LPAd protobuf, PSK/AES-CCM secure channel, SCARD bridge, ES10 quirks (`A0` wrapper, `SW 91xx`)
* [`protocol/nble.md`](protocol/nble.md) — password/key derivation, 3DES handshake, `counter‖apdu‖sum16` framing
* [`protocol/beeesim.md`](protocol/beeesim.md) — `[total,index]` grouping over `0xAE30`, no MANAGE CHANNEL

and [`protocol/README.md`](protocol/README.md) for the side-by-side comparison.

## Layout

```
.
├── protocol/        one document per card + README.md (comparison)
├── src/py/blpa/     Python toolkit
│   ├── base.py        Card interface (info/eid/profiles/enable/disable/delete)
│   ├── tlv.py         BER-TLV + the SGP.22 ES10 commands shared by all cards
│   ├── linklan.py     LPAd: protobuf, PSK secure channel, SCARD bridge
│   ├── nble.py        9eSIM / NBLE: 3DES handshake, framed APDUs, checksums
│   ├── beeesim.py     BeeSIM: [total,index] grouping over 0xAE30
│   └── cli.py         `python -m blpa …`
└── src/web/         Web Bluetooth console (see src/web/README.md)
```

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r src/py/requirements.txt      # bleak, cryptography
export PYTHONPATH=src/py
```

## Python quick start

```bash
python -m blpa --card 9esim info                       # EID + derived password
python -m blpa --card beeesim profiles                 # no credentials needed
python -m blpa --card linklan --password "$CARD_PW" profiles
python -m blpa --card auto eid                         # beeesim → 9esim → linklan
```

Example output — identifiers truncated to their first eight digits, as
everywhere else in this repository ([data policy](#what-is-and-is-not-in-this-repository)):

```
$ python -m blpa --card linklan --password "$CARD_PW" profiles
[0] 89444765…  disabled  Speedtest Travel  BetterRoaming
[1] 89444765…  enabled   BetterRoaming     BetterRoaming

$ python -m blpa --card beeesim profiles
[0] 89000000…  disabled  R&S              R&S
[1] 89444765…  enabled   Speedtest Travel  BetterRoaming
[2] 89444765…  disabled  -                 BetterRoaming

$ python -m blpa --card 9esim info
{ "kind": "9esim", "name": "9eSIM…", "eid": "89086029…", "defaultPassword": "…" }

$ python -m blpa --card linklan --password "$CARD_PW" eid
89044045…
```

Commands: `info`, `eid`, `profiles [--json]`, `enable|disable|delete|nickname <iccid>`,
`apdu <hex>`, and for 9eSIM also `rekey <6-hex-suffix> <password> --yes` (changes
the card's BLE name and password together — verified on hardware, see
[protocol/nble.md §7](protocol/nble.md)); global `--card auto|linklan|9esim|beeesim`,
`--address`, `--name`, `--password`, `--json`.  The 9eSIM backend answers to both
`--card 9esim` and `--card nble` (same implementation).

## Credentials

| card | how the key is obtained | environment |
|---|---|---|
| **Linklan** | `--password` — the card's connection password, whose factory default is **the last six digits of the EID** — or the raw 32-byte PSK | `LINKLAN_PASSWORD`, `LINKLAN_PSK` |
| **9eSIM** | `--password`, default **the last six characters of the BLE name, reversed** (`DEMO123456` → `654321`) | `ESIM9_PASSWORD` |
| **BeeSIM** | nothing — the card has no authentication | — |

`--card auto` skips Linklan unless a password or PSK is configured, and prints a
hint explaining why.

## Web Bluetooth console

```bash
cd src/web && python3 -m http.server 8000     # open http://localhost:8000 in Chrome/Edge
```

One page for all three families.  There is no card-type selector: you pick a
device and the family is detected from its name (`BeeSIM*`, `9eSIM*` /
`esim_writer*`, `*BLE-eSIM*`).  Only Linklan *requires* a credential; 9eSIM's field is optional and prefilled with
its name-derived default (a card may have been re-keyed).  Both are remembered
**per card** in `localStorage` with a *Forget* button — for 9eSIM only when the
password differs from the derivable default.  BeeSIM needs none, and nothing is
ever stored for it.  A connected 9eSIM also gets a **Rekey** panel: it sends the
same `30 27 00 00 09 …` vendor command the CLI's `rekey` uses (hardware-verified),
which renames the card and gives it a new key.

The page implements the crypto itself — HMAC-SHA256 through WebCrypto, AES-CCM
built on AES-CBC/CTR, and a pure-JS 3DES — and both suites pin it:

```bash
node src/web/test.mjs              # crypto + TLV vectors vs the Python client, envelope shapes
node src/web/test-linklan-mock.mjs # a whole Linklan session against a mock GATT card
```

`test.mjs`: `aesccm · aesccm D · 3des · 3des D · tlv · cmdEnable · 9esim key ·
resultCode · authframe · rekey · classify` — 11/11.
`test-linklan-mock.mjs`: `handshake · eid · profiles · enable` — 4/4.

## Deploying the web console

`src/web` is the published artefact: **static, no backend**, so GitHub Pages can
serve it.  The workflow in `.github/workflows/publish-web.yml` runs on every push
that touches `src/web` — on any branch except `web` (this repo's default is
`master`, so there is deliberately no `branches: [main]` filter) — or on demand, runs both node test suites, and force-pushes
a clean copy to the **`web`** branch (only `index.html`, the three `.js` modules,
`CNAME` and `.nojekyll` — the toolkit, protocol docs, tests and vectors are not
published).

Setting it up once:

1. **Settings → Pages**: source = *branch `web`*, folder `/`; custom domain
   `blpa.cyyself.name` (the `src/web/CNAME` file already carries it); tick
   *Enforce HTTPS*.
2. **DNS**: `CNAME blpa → <your-user>.github.io`.
3. Nothing else — the workflow uses the default `GITHUB_TOKEN` with
   `contents: write`, and attributes the publish commit to whoever pushed
   (`<actor-id>+<actor>@users.noreply.github.com`, so no real address ends up on
   the public branch).

Locally it is still just:

```bash
cd src/web && python3 -m http.server 8000    # http://localhost:8000
```

## Security comparison

All three cards expose profile management over BLE — what differs is only what
stands in front of it.  Details and transcripts in each `protocol/*.md`
(“Security notes”), plus the deeper report in the sibling `Linklan` checkout.

| | **Linklan / Linksfield** | **9eSIM (NBLE)** | **BeeSIM** |
|---|---|---|---|
| transport authentication | PSK handshake, then an AES-CCM session | password → 3DES challenge/response | **none at all** |
| default credential | `HMAC_SHA256(password, "SecurePbChannel")`, password = **last 6 digits of the EID** | **reverse of the last 6 characters** of the advertised name | – |
| derivable from public data? | yes — the EID is printed / shown in the phone | yes — the name is broadcast in every advertising packet | – |
| offline attack on a **sniffed handshake** | **1.3 s** for the 6-digit space (305 k candidates/s): `devRandom`, `cliRandom` and the HMAC answer travel in clear — confirmed on a live card, the recovered key then decrypts the captured session | **yes, ~2 min** for the full 2²⁴ space (one core; seconds on a GPU) — the captured challenge/response pair verifies any candidate | – |
| online guessing | 0.19 guesses/s (≈5 s penalty per failure) → 6 digits ≈ 60 days | 0.46 guesses/s (one guess per connection) → 10⁶ ≈ 25 days, full 2²⁴ ≈ 418 days | – |
| BLE link-layer encryption (pairing/bonding) | none | none | none |
| what a passive sniffer sees | handshake in clear, then AES-CCM frames | handshake ciphertexts, then **plaintext APDUs** | **everything in plaintext** |
| lockout / attempt counter | none | none | none |
| credential protects | profile ops (enable/disable/delete/rename), notifications, the APDU bridge | same | nothing |
| profile confidentiality | GSMA PKI — chain verified to *GSM Association RSP2 Root CI1*, profiles bound per eUICC | same | same |

What holds on all three: the transport key never yields profile key material.
Ki/OPc stay inside the eUICC, and a profile cannot be cloned to another card —
verified for Linklan by checking the eUICC certificate chain and the
`AuthenticateServer` signature offline.

The BLE link itself is **not** encrypted — none of the three cards pairs or bonds,
so the vendor security is purely application level.  With a BLE sniffer that
follows the connection (Ubertooth, an nRF52 dongle, a HackRF) a passive attacker
records the handshake of a legitimate session, which is enough to run the offline
attack above; on 9eSIM and BeeSIM the rest of the traffic is readable without any
cracking at all.

Worst case per card, from an attacker with BLE adjacency:

* **BeeSIM** — full control immediately: enable/disable/delete/rename, read the
  EID, change the radio's TX power. No credential exists, so there is nothing to
  brute-force and nothing to re-key.
* **9eSIM** — full control as soon as the name is seen (default password). If the
  card was re-keyed, guessing costs days-to-months (table above); there is no
  lockout to stop it.
* **Linklan** — full control once the EID tail is known; if the PSK leaks (it is
  printed in the vendor app's logcat) the password falls in about a second. The
  card's only rate limit is a fixed 5 s delay per failure.

Hardening that actually helps:

| card | what to do |
|---|---|
| **Linklan** | rotate the PSK to a random 32-byte value and keep it out of logs; treat the EID as sensitive, since its tail is the default password |
| **9eSIM** | `rekey` to a password that is *not* the reversed name (CLI `rekey`, or the web console's Rekey panel); the new password is no longer derivable from the advertisement |
| **BeeSIM** | nothing in-protocol — keep it physically controlled and out of uncontrolled radio range; treat it as trusted hardware |

Common advice: assume anything sent over BLE is observable — cards stop
advertising while connected, so a card that is not in use should be powered down or
out of range; one central at a time means an attacker in range can also simply
block the legitimate user.

## What is (and is not) in this repository

Verified behaviour, byte layouts and the quirks of each card are documented in
`protocol/`.  **Card identifiers are truncated to their first eight digits**
(`89044045…`, `89086029…`, `89049032…`, ICCIDs `89444765…`) — that part is the
MNO/vendor prefix.  The tail of an EID is deliberately withheld because the
vendor uses its last six digits as the card password, and no PSK, password, IMEI,
SN or BLE address from a real card appears in the code or the tests — those use
demo values (`8900000000000000001`, `DEMO123456` → `654321`).  The documentation
and the example output above show only the eight-digit prefixes of real cards.

## Notes and caveats

* A card accepts **one central**: stop the phone app and any Python client before
  a browser (or another script) connects.  Cards also stop advertising while
  connected, which is why `--card auto` attempts families in turn instead of
  trusting a single scan.
* Web Bluetooth needs `https://` or `http://localhost` and a user gesture.
  Chrome/Edge work on desktop and Android; **Safari has no Web Bluetooth**, so on
  iOS/iPadOS open the page in
  [Bluefy — Web BLE Browser](https://apps.apple.com/us/app/bluefy-web-ble-browser/id1492822055)
  (the page detects the missing API and links to it).  The API exposes no MTU, so
  the Linklan transport starts at 244-byte writes and halves on failure.
* **BeeSIM has no MANAGE CHANNEL**: `00 70 00 01 00` answers `6A86`; the applet is
  selected with `CLA = 1` and only the ES10 traffic uses `CLA = 0x81`.
* **Profile download is not part of this repository yet.**  It was implemented
  and tested against a real SM-DP+ in the sibling project
  (`Linklan/linklan/download.py`, SGP.22 + ES9+), which installs, switches and
  deletes real profiles on the Linklan card; porting it here is a matter of
  reusing that module with the transport-agnostic `store_data` each backend
  already provides.  The browser cannot do the ES9+ leg alone either way:
  SM-DP+ certificates chain to the GSMA RSP CI roots (not in a browser trust
  store) and the servers send no CORS headers, so it needs a localhost helper.
* Security: all three cards expose profile management to anyone in radio range who
  knows (or can derive) the key — see the "security notes" section of each
  protocol document.  Treat a paired card as trusted hardware.

## License

MIT — see [LICENSE](LICENSE).
