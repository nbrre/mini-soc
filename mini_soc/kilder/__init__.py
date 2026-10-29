"""Innlesing av kilder. Hver kilde gjør om sitt format til felles Hendelse-objekter."""
from __future__ import annotations

import pathlib

from ..modeller import Hendelse
from .epost import les_eposter
from .helpdesk import les_helpdesk
from .innlogging import les_auth_log, les_innlogginger_csv


def les_mappe(mappe: str | pathlib.Path, aar: int = 2026) -> list[Hendelse]:
    """Leser alle kjente filer i en mappe og returnerer hendelser sortert på tid."""
    mappe = pathlib.Path(mappe)
    hendelser: list[Hendelse] = []
    for fil in sorted(mappe.glob("*.log")):
        hendelser += les_auth_log(fil, aar)
    for fil in sorted(mappe.glob("*.csv")):
        hendelser += les_innlogginger_csv(fil)
    for fil in sorted(mappe.glob("*helpdesk*.json")):
        hendelser += les_helpdesk(fil)
    if (mappe / "eposter").is_dir():
        hendelser += les_eposter(mappe / "eposter")
    return sorted(hendelser, key=lambda h: h.tid)
