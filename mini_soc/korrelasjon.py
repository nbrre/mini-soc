"""Kobler varsler sammen til hendelsessaker.

To varsler havner i samme sak når de deler en bruker eller ekstern IP-adresse og ligger
innenfor et tidsvindu fra hverandre. Interne nett brukes ikke som kobling, ellers ville
alt fra kontoret blitt én stor sak.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import timedelta

from .modeller import ALVOR, Varsel

INTERNE_NETT = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("10.0.0.0/8")]
VINDU = timedelta(hours=6)

# Grov kobling fra MITRE-teknikk til fase i angrepet (taktikk)
TAKTIKK = {"T1566": "Første tilgang", "T1110": "Tilgang til påloggingsdata", "T1078": "Bruk av gyldige kontoer",
           "T1486": "Ødeleggelse/påvirkning"}
FASE_REKKEFOLGE = list(TAKTIKK.values())


def taktikk(mitre: str) -> str:
    return TAKTIKK.get(mitre.split(".")[0], "Annet")


def _intern(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in nett for nett in INTERNE_NETT)
    except ValueError:
        return False


def _koblinger(v: Varsel) -> set[str]:
    return {e for e in v.entiteter if not (e.startswith("ip:") and _intern(e[3:]))}


@dataclass
class Sak:
    varsler: list[Varsel]
    id: int | None = None
    status: str = "ny"
    rapport: dict | None = field(default=None)

    @property
    def start(self):
        return min(v.tid for v in self.varsler)

    @property
    def slutt(self):
        return max(v.tid for v in self.varsler)

    @property
    def faser(self) -> list[str]:
        sett = {taktikk(v.mitre) for v in self.varsler}
        return [f for f in FASE_REKKEFOLGE if f in sett]

    @property
    def alvor(self) -> str:
        hoyest = max(v.poeng for v in self.varsler)
        if len(self.faser) >= 3:          # en hel angrepskjede er verre enn summen av delene
            hoyest = min(hoyest + 1, 4)
        return next(n for n, p in ALVOR.items() if p == hoyest)

    @property
    def brukere(self) -> list[str]:
        return sorted({b for v in self.varsler for b in v.brukere})

    @property
    def ipadresser(self) -> list[str]:
        return sorted({i for v in self.varsler for i in v.ipadresser})

    @property
    def tittel(self) -> str:
        hoved = max(self.varsler, key=lambda v: (v.poeng, v.tid))
        ekstra = f" (+{len(self.varsler) - 1} relaterte varsler)" if len(self.varsler) > 1 else ""
        return hoved.tittel + ekstra

    def til_dict(self) -> dict:
        return {"id": self.id, "tittel": self.tittel, "alvor": self.alvor, "status": self.status,
                "start": self.start.isoformat(timespec="seconds"), "slutt": self.slutt.isoformat(timespec="seconds"),
                "brukere": self.brukere, "ipadresser": self.ipadresser, "faser": self.faser,
                "varsler": [v.til_dict() for v in sorted(self.varsler, key=lambda v: v.tid)], "rapport": self.rapport}


def korreler(varsler: list[Varsel], vindu: timedelta = VINDU) -> list[Sak]:
    """Union-find over varsler som deler kobling og ligger innenfor vinduet."""
    forelder = list(range(len(varsler)))

    def finn(i):
        while forelder[i] != i:
            forelder[i] = forelder[forelder[i]]
            i = forelder[i]
        return i

    for i, a in enumerate(varsler):
        for j in range(i + 1, len(varsler)):
            b = varsler[j]
            if _koblinger(a) & _koblinger(b) and abs(a.tid - b.tid) <= vindu:
                forelder[finn(i)] = finn(j)

    grupper: dict[int, list[Varsel]] = {}
    for i, v in enumerate(varsler):
        grupper.setdefault(finn(i), []).append(v)
    saker = [Sak(sorted(g, key=lambda v: v.tid)) for g in grupper.values()]
    return sorted(saker, key=lambda s: (-ALVOR[s.alvor], s.start))
