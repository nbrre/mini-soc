"""Hele løypa: les kilder → regler → korrelasjon → lagring."""
from __future__ import annotations

import pathlib

from .kilder import les_mappe
from .korrelasjon import korreler
from .lagring import Lager
from .regler import kjor_regler


def kjor(mappe: str | pathlib.Path, lager: Lager | None = None) -> Lager:
    lager = lager or Lager()
    hendelser = les_mappe(mappe)
    lager.lagre_hendelser(hendelser)
    varsler = kjor_regler(hendelser)
    saker = korreler(varsler)
    lager.lagre_saker(saker)
    lager.logg("system", "innlesing", {"mappe": str(mappe), "hendelser": len(hendelser),
                                        "varsler": len(varsler), "saker": len(saker)})
    return lager
