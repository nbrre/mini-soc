"""Innlogginger fra Linux auth.log (sshd) og CSV-eksport (f.eks. Microsoft Entra ID)."""
from __future__ import annotations

import csv
import pathlib
import re
from datetime import datetime

from ..modeller import Hendelse

SSHD = re.compile(
    r"^(?P<mnd>\w{3})\s+(?P<dag>\d+)\s+(?P<kl>[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<res>Failed|Accepted) \w+ for (?:invalid user )?(?P<bruker>\S+) from (?P<ip>[\d.]+)"
)
MND = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def les_auth_log(sti: str | pathlib.Path, aar: int = 2026) -> list[Hendelse]:
    ut = []
    for linje in pathlib.Path(sti).read_text(encoding="utf-8").splitlines():
        m = SSHD.match(linje)
        if not m:
            continue
        tid = datetime.strptime(f"{aar}-{MND[m['mnd']]:02d}-{int(m['dag']):02d} {m['kl']}", "%Y-%m-%d %H:%M:%S")
        ok = m["res"] == "Accepted"
        ut.append(Hendelse(tid, "ssh", "innlogging_ok" if ok else "innlogging_feil",
                           bruker=m["bruker"], ip=m["ip"], rå=linje))
    return ut


def les_innlogginger_csv(sti: str | pathlib.Path) -> list[Hendelse]:
    """Kolonner: tid, bruker, ip, land, resultat (ok/feil), app."""
    ut = []
    with pathlib.Path(sti).open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            ok = r["resultat"].strip().lower() in ("ok", "success", "suksess")
            ut.append(Hendelse(datetime.fromisoformat(r["tid"]), "entra", "innlogging_ok" if ok else "innlogging_feil",
                               bruker=r["bruker"].split("@")[0].lower(), ip=r["ip"], land=r.get("land", "").upper(),
                               detaljer={"app": r.get("app", "")}, rå=",".join(r.values())))
    return ut
