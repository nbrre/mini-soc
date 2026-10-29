"""Måler hvor godt reglene og korrelasjonen treffer på scenarioer med fasit.

Hvert scenario i eval/ har en mappe med data og en fasit.json:
  {"saker": [{"regler": ["phishing", ...], "alvor": "kritisk"}, ...]}
Et scenario uten saker i fasiten måler falske alarmer.
"""
from __future__ import annotations

import json
import pathlib

from .kilder import les_mappe
from .korrelasjon import korreler
from .regler import kjor_regler


def evaluer_scenario(mappe: pathlib.Path) -> dict:
    fasit = json.loads((mappe / "fasit.json").read_text(encoding="utf-8"))["saker"]
    saker = korreler(kjor_regler(les_mappe(mappe)))
    funnet = [{"regler": sorted({v.regel for v in s.varsler}), "alvor": s.alvor} for s in saker]
    forventet = [{"regler": sorted(f["regler"]), "alvor": f["alvor"]} for f in fasit]
    treff = [f for f in forventet if f in funnet]
    return {"scenario": mappe.name, "forventet": len(forventet), "funnet": len(funnet), "riktige": len(treff),
            "presisjon": round(len(treff) / len(funnet), 2) if funnet else 1.0,
            "gjenfinning": round(len(treff) / len(forventet), 2) if forventet else 1.0,
            "mangler": [f for f in forventet if f not in funnet], "ekstra": [f for f in funnet if f not in forventet]}


def evaluer_alle(rot: str | pathlib.Path = "eval") -> list[dict]:
    return [evaluer_scenario(m) for m in sorted(pathlib.Path(rot).iterdir()) if (m / "fasit.json").exists()]
