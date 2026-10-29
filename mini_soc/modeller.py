"""Felles datamodell. Alle kilder (innlogginger, e-post, helpdesk) blir til Hendelse- og Varsel-objekter."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

ALVOR = {"lav": 1, "middels": 2, "høy": 3, "kritisk": 4}


@dataclass
class Hendelse:
    """Én rå hendelse fra en kilde, f.eks. én innlogging."""
    tid: datetime
    kilde: str                      # "ssh", "entra", "epost", "helpdesk"
    type: str                       # "innlogging_feil", "innlogging_ok", "epost", "sak"
    bruker: str = ""
    ip: str = ""
    land: str = ""
    detaljer: dict = field(default_factory=dict)
    rå: str = ""

    def til_dict(self) -> dict:
        d = asdict(self)
        d["tid"] = self.tid.isoformat(timespec="seconds")
        return d


@dataclass
class Varsel:
    """Et funn fra en deteksjonsregel."""
    regel: str
    tittel: str
    alvor: str
    tid: datetime
    kilde: str
    mitre: str                      # MITRE ATT&CK-teknikk, f.eks. "T1110.003"
    brukere: list[str] = field(default_factory=list)
    ipadresser: list[str] = field(default_factory=list)
    bevis: list[str] = field(default_factory=list)
    id: int | None = None

    @property
    def poeng(self) -> int:
        return ALVOR[self.alvor]

    @property
    def entiteter(self) -> set[str]:
        return {f"bruker:{b}" for b in self.brukere if b} | {f"ip:{i}" for i in self.ipadresser if i}

    def til_dict(self) -> dict:
        d = asdict(self)
        d["tid"] = self.tid.isoformat(timespec="seconds")
        return d
