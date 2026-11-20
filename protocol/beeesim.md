# BeeSIM reader — protocol

> **Status** verified on hardware (EID `89049032…`, three profiles, one enabled);
> full identifiers and the reader's address are withheld.
> **Implementation** `src/py/blpa/beeesim.py`, `src/web/transports.js` (`BeeSimCard`)

## 1. Link layer

| item | value |
|---|---|
| advertised name | `BeeSIM-000000` (prefix `BeeSIM`) |
| service | `0000ae30-0000-1000-8000-00805f9b34fb` (16-bit `0xAE30`) |
| write | `0000ae01-0000-1000-8000-00805f9b34fb`, write **without** response |
| notify | `0000ae02-0000-1000-8000-00805f9b34fb` |
| MTU | 515 on the card used |
| payload | plain ISO-7816 APDUs — **no authentication layer** |

## 2. Framing (grouped packets, 18 bytes per group)

```
packet   = [total_groups, group_index (1-based)] ‖ up to 18 bytes of payload
outbound = the APDU split into 18-byte groups, one ATT write per group
inbound  = same scheme; index 1 starts a new message, and the message is
           complete when group_index == total_groups
```

## 3. Channel initialisation (as measured)

**There is no MANAGE CHANNEL.** `00 70 00 01 00` is answered with `6A86`, and
`00 70 80 01 00` is not answered at all.  The applet is selected directly with
`CLA = logical channel`:

```
80 AA 00 00 0A A9 08 81 00 82 01 01 83 01 07     "terminal capabilities" -> 9000 (optional)
01 A4 04 00 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00     SELECT ISD-R -> 61 21
01 C0 00 00 21                                   GET RESPONSE -> FCI + 9000
```

Note the two different `CLA`s: the SELECT/GET-RESPONSE pair uses the *channel*
class (`0x01`), while ES10 traffic to the same applet uses the proprietary class
`0x80 | channel` (`0x81`) and its `61 xx` replies are fetched with `0x81` too.

`CLA` for ES10 traffic is `0x80 | logical_channel` (`0x81` on channel 1).

```
GET RESPONSE  81 C0 00 00 <le>            repeat while SW1 == 0x61
STORE DATA    81 E2 <p1> <block> <lc> <data>
              P1 = 0x11 while more blocks follow, 0x91 on the last, lc ≤ 239
```

`SW 6881` = the logical channel is gone → re-run the channel init, retry once.

## 4. Verified transcript

```
>>> 80 AA 00 00 0A A9 08 81 00 82 01 01 83 01 07        -> 90 00
>>> 01 A4 04 00 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00   -> 61 21
>>> 01 C0 00 00 21
    <- 6F 1F 84 10 A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00
       A5 04 9F 65 01 FF E0 05 82 03 02 02 02  90 00
>>> 81 E2 91 00 06 BF 3E 03 5C 01 5A                     -> 61 15
>>> 81 C0 00 00 15
    <- BF 3E 12 5A 10 89 04 90 32 … (EID, prefix shown)  90 00
>>> 81 E2 91 00 03 BF 2D 00                              -> 61 CA
>>> 81 C0 00 00 CA
    <- BF 2D 81 C6 A0 81 C3 <three E3 entries> 90 00
```

That card held three profiles (one enabled `Speedtest Travel`, two disabled, all
ICCIDs starting `89444765…`) and a rename (`BF 29`) wrote successfully, so the
full ES10 write path is exercised, not just reads.

## 5. Vendor commands (CLA 0xA0)

| APDU | meaning |
|---|---|
| `A0 3E <0-4> 00 00` | set BLE TX power (0 = min, 4 = max) |
| `A0 3F 00 00 00` | soft reset of the eUICC (ATR / refresh) |
| `00 00 00 00 F4 01 01` | firmware-upgrade progress query |
| `80 AA 00 00 0A A9 08 81 00 82 01 01 83 01 07` | terminal capabilities |

## 6. ES10 command set

```
EID        BF 3E 03 5C 01 5A
profiles   BF 2D 00                        (this firmware accepts it without a tag list)
enable     BF 31 { A0 { 5A <iccid> }, 81 01 00 }
disable    BF 32 { A0 { 5A <iccid> }, 81 01 00 }
delete     BF 33 { 5A <iccid> }
nickname   BF 29 { 5A <iccid>, 90 <utf8> }
notify     BF 28 00  /  BF 2B { A0 { 80 <seq> } }  /  BF 30 { 80 <seq> }
```

Result codes are the SGP.22 ones (`0` ok, `1` not found, `2` wrong state,
`3` policy, `4` profile error, `5` busy).

## 7. ProfileInfo on this card

```
BF2D { A0 { E3 { 5A <iccid>, 4F 10 <isdpAid>, 9F70 <state>, 90 <nickname>,
               91 <name>, 92 <provider>, 95 <class> } … } }
```

Unlike the Linklan firmware it also reports `4F` (the ISD-P AID). `9F70 = 01`
means enabled.  An empty slot answers `BF2D 02 A0 00`.

## 8. Security notes

The link layer is not encrypted either, so a sniffer sees every APDU in clear —
including the EID and the profile list.  BeeSIM exposes profile management with
**no authentication at all**: any BLE
central in range can enable, disable, delete or rename profiles, read the EID and
change the radio's TX power.  The firmware also offers no way to switch the BLE
radio off (the reference implementation carries the same warning).  Treat the
card as trusted hardware and keep it away from uncontrolled radio environments.

## 9. Differences from the other two cards

| | Linklan | 9eSIM | BeeSIM |
|---|---|---|---|
| transport auth | PSK + AES-CCM | password → 3DES | none |
| framing | length-prefixed protobuf | header byte + sum16 | `[total, index]` |
| channel | logical 4 via a bridge | basic channel | logical 1 |
| `A0` wrapper for profile ops | **required** | accepted | accepted |
