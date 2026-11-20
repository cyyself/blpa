"""Unified CLI: `python -m blpa <command> [--card auto|linklan|9esim|beeesim]`."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Optional

from .base import BlpaError, Card
from .beeesim import BeeSimCard
from .nble import NbleCard
from .linklan import LinklanCard

BACKENDS = {"linklan": LinklanCard, "9esim": NbleCard, "nble": NbleCard,
            "beeesim": BeeSimCard}   # "nble" and "9esim" are the same backend


def build(kind: str, args) -> Card:
    if kind == "linklan":
        psk = os.environ.get("LINKLAN_PSK")
        return LinklanCard(address=args.address, name=args.name,
                           psk=bytes.fromhex(psk) if psk else None,
                           password=args.password or os.environ.get("LINKLAN_PASSWORD"))
    if kind in ("9esim", "nble"):
        return NbleCard(address=args.address, name=args.name,
                         password=args.password or os.environ.get("ESIM9_PASSWORD"))
    return BeeSimCard(address=args.address, name=args.name)


def pick(profiles, needle: str):
    for i, p in enumerate(profiles):
        if needle in (p.iccid, p.nickname, p.name, str(i)):
            return p
    raise BlpaError(f"no profile matching {needle!r}")


async def detect_all() -> list:
    """Which card families are advertising right now, in preference order."""
    from bleak import BleakScanner
    seen = []
    for _ in range(2):        # cards stop advertising while connected, so sample twice
        seen += [((d.name or "").lower()) for d in await BleakScanner.discover(timeout=8)]
    tests = (("beeesim", lambda n: n.startswith("beeesim")),
             ("9esim", lambda n: n.startswith("9esim") or "esim_writer" in n),
             ("linklan", lambda n: "ble-esim" in n))
    found = [kind for kind, test in tests if any(test(n) for n in seen)]
    if not found:
        raise BlpaError("no supported card found (linklan / 9esim / beeesim)")
    return found


HINTS = {
    "linklan": "the card needs its PSK or its connection password (the EID's last "
               "six digits): pass --password <pw> or --psk/LINKLAN_PSK",
}


async def run(args) -> int:
    if args.card == "auto":
        # Try instead of guessing: the families need different credentials and
        # cards stop advertising while another central holds them.
        kinds = ["beeesim", "9esim"]
        if (args.password or os.environ.get("LINKLAN_PSK")
                or os.environ.get("LINKLAN_PASSWORD") or os.environ.get("ESIM9_PASSWORD")):
            kinds.append("linklan")
        else:
            print("# linklan skipped: no --password/--psk given (see hint below)",
                  file=sys.stderr)
    else:
        kinds = [args.card]
    card = None
    errors = []
    for kind in kinds:
        candidate = build(kind, args)
        try:
            await candidate.connect()
        except BlpaError as exc:
            hint = HINTS.get(kind)
            errors.append(f"{kind}: {exc}" + (f"\n  hint: {hint}" if hint else ""))
            print(f"# {kind}: {exc}", file=sys.stderr)
            continue
        card = candidate
        if len(kinds) > 1:
            print(f"# using {kind}", file=sys.stderr)
        break
    if card is None:
        raise BlpaError("no card could be opened:\n" + "\n".join(errors))
    try:
        if args.command == "info":
            print(json.dumps((await card.info()).as_dict(), indent=2))
        elif args.command == "eid":
            print(await card.eid())
        elif args.command == "profiles":
            profiles = await card.profiles()
            if args.json:
                print(json.dumps([p.as_dict() for p in profiles], indent=2))
            else:
                for i, p in enumerate(profiles):
                    print(f"[{i}] {p.iccid}  {'enabled ' if p.enabled else 'disabled'}  "
                          f"{p.nickname or p.name or '-'}  {p.provider}")
        elif args.command in ("enable", "disable", "delete", "nickname"):
            profile = pick(await card.profiles(), args.profile)
            if args.command == "enable":
                await card.enable(profile.iccid)
            elif args.command == "disable":
                await card.disable(profile.iccid)
            elif args.command == "delete":
                if not args.yes:
                    print(f"refusing to delete {profile.iccid} without --yes", file=sys.stderr)
                    return 2
                await card.delete(profile.iccid)
            else:
                await card.nickname(profile.iccid, args.value)
            print(f"{args.command} {profile.iccid}: ok")
        elif args.command == "rekey":
            if not hasattr(card, "set_name_and_password"):
                raise BlpaError(f"--card {kind} does not support changing the password")
            if not args.yes:
                print("refusing without --yes: this renames the card and changes its key; "
                      "you must reconnect with the new name and password", file=sys.stderr)
                return 2
            await card.set_name_and_password(args.suffix, args.password)
            print(f"card re-keyed; reconnect with the new name suffix {args.suffix} "
                  f"and the new password")

        elif args.command == "apdu":
            if not hasattr(card, "transmit"):
                raise BlpaError(f"{kind} has no raw APDU path")
            rsp = await card.transmit(bytes.fromhex(args.hex))
            print(rsp.hex().upper())
        return 0
    finally:
        await card.disconnect()


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="blpa", description=__doc__,
                            epilog="--card: linklan | 9esim (alias nble) | beeesim; "
                                   "\"auto\" tries them in turn")
    p.add_argument("--card", default=os.environ.get("BLPA_CARD", "auto"),
                   choices=["auto", *BACKENDS])
    p.add_argument("--address")
    p.add_argument("--name")
    p.add_argument("--password")
    p.add_argument("--json", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("info", "eid", "profiles"):
        sub.add_parser(name)
    sp = sub.add_parser("rekey", help="9eSIM only: change the BLE name suffix and password")
    sp.add_argument("suffix", help="new 6 hex character name suffix (e.g. 250400)")
    sp.add_argument("password", help="new password (6 hex characters, or anything → CRC24)")
    sp.add_argument("--yes", action="store_true", help="confirm (the card renames itself)")
    for name in ("enable", "disable", "delete", "nickname"):
        sp = sub.add_parser(name)
        sp.add_argument("profile")
        if name == "nickname":
            sp.add_argument("value")
        if name == "delete":
            sp.add_argument("--yes", action="store_true")
    sp = sub.add_parser("apdu", help="send a raw hex APDU (advanced)")
    sp.add_argument("hex")
    args = p.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except BlpaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
