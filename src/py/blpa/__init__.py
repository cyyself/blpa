"""blpa — one Python toolkit for three BLE eSIM reader families.

    linklan   Linksfield/Linklan "BLE-eSIM"   (LPAd protobuf + PSK secure channel)
    9esim     9eSIM / NBLE-SIM writers          (3DES-authenticated framed APDU, nble.py)
    beeesim   BeeSIM readers                   (grouped APDU over service 0xAE30)

Each backend exposes the same small interface (see ``base.Card``) so the CLI and
the WebBLE app can talk to any of them.
"""
__version__ = "0.1.0"

CARD_KINDS = ("linklan", "9esim", "beeesim")
