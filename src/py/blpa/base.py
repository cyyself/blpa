"""Common interface every card backend implements."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class BlpaError(RuntimeError):
    pass


@dataclass
class Profile:
    iccid: str
    enabled: bool = False
    nickname: str = ""
    name: str = ""
    provider: str = ""
    profile_class: int = 0

    def as_dict(self) -> dict:
        return {
            "iccid": self.iccid, "enabled": self.enabled, "nickname": self.nickname,
            "name": self.name, "provider": self.provider,
            "profileClass": self.profile_class,
        }


@dataclass
class CardInfo:
    kind: str
    name: str
    address: str
    eid: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = {"kind": self.kind, "name": self.name, "address": self.address,
             "eid": self.eid}
        d.update(self.extra)
        return d


class Card:
    """Duck-typed interface of the three backends."""

    kind = "?"

    async def connect(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    async def disconnect(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    async def info(self) -> CardInfo:  # pragma: no cover - abstract
        raise NotImplementedError

    async def eid(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    async def profiles(self) -> List[Profile]:  # pragma: no cover - abstract
        raise NotImplementedError

    async def enable(self, iccid: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    async def disable(self, iccid: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    async def delete(self, iccid: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError
