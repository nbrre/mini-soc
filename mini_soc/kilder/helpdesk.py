"""Supportsaker fra helpdesk (JSON med tid, avsender, emne, tekst)."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime

from ..modeller import Hendelse


def les_helpdesk(sti: str | pathlib.Path) -> list[Hendelse]:
    ut = []
    for r in json.loads(pathlib.Path(sti).read_text(encoding="utf-8")):
        ut.append(Hendelse(datetime.fromisoformat(r["tid"]), "helpdesk", "sak",
                           bruker=r["avsender"].split("@")[0].lower(),
                           detaljer={"id": r["id"], "emne": r["emne"], "tekst": r["tekst"]},
                           rå=f"{r['emne']}\n{r['tekst']}"))
    return ut
