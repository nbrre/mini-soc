"""Deteksjonsregler. Hver regel tar alle hendelser og returnerer varsler, merket med MITRE ATT&CK.

Terskler og tidsvinduer ligger i TERSKLER og kan justeres per kunde.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from .modeller import Hendelse, Varsel

TERSKLER = {
    "brute_force_antall": 5, "brute_force_vindu_min": 10,
    "spraying_brukere": 5, "spraying_vindu_min": 15,
    "suksess_etter_feil": 3, "suksess_vindu_min": 30,
    "umulig_reise_timer": 3,
    "arbeidstid": (6, 22),
    "phishing_poeng": 6,
}
PRIVILEGERTE = {"root", "admin", "administrator"}
KOMPROMITTERT = re.compile(r"(?i)(klikket|klikka|trykket) på .{0,20}(lenke|link).{0,200}(passord|bankid|koden)|"
                           r"(skrev|tastet|oppga) (inn )?(passord|bankid|koden)")
LOSEPENGER = re.compile(r"(?i)løsepenge|ransomware|\.locked\b|filene? (er|ble) kryptert")


def _feil(h): return h.type == "innlogging_feil"
def _ok(h): return h.type == "innlogging_ok"


def brute_force(hs: list[Hendelse]) -> list[Varsel]:
    t, ut, grupper = TERSKLER, [], defaultdict(list)
    for h in filter(_feil, hs):
        grupper[(h.bruker, h.ip)].append(h)
    for (bruker, ip), liste in grupper.items():
        for i, start in enumerate(liste):
            vindu = [h for h in liste[i:] if h.tid - start.tid <= timedelta(minutes=t["brute_force_vindu_min"])]
            if len(vindu) >= t["brute_force_antall"]:
                ut.append(Varsel("brute_force", f"{len(vindu)} feilede innlogginger mot «{bruker}» fra {ip}",
                                 "middels", vindu[-1].tid, vindu[0].kilde, "T1110.001", [bruker], [ip],
                                 [h.rå for h in vindu[:3]]))
                break
    return ut


def password_spraying(hs: list[Hendelse]) -> list[Varsel]:
    t, ut, per_ip = TERSKLER, [], defaultdict(list)
    for h in filter(_feil, hs):
        per_ip[h.ip].append(h)
    for ip, liste in per_ip.items():
        for i, start in enumerate(liste):
            vindu = [h for h in liste[i:] if h.tid - start.tid <= timedelta(minutes=t["spraying_vindu_min"])]
            brukere = sorted({h.bruker for h in vindu})
            if len(brukere) >= t["spraying_brukere"]:
                ut.append(Varsel("password_spraying", f"{ip} prøvde {len(brukere)} ulike brukere",
                                 "høy", vindu[-1].tid, vindu[0].kilde, "T1110.003", brukere, [ip],
                                 [h.rå for h in vindu[:3]]))
                break
    return ut


def suksess_etter_feil(hs: list[Hendelse]) -> list[Varsel]:
    t, ut = TERSKLER, []
    for h in filter(_ok, hs):
        feil = [x for x in hs if _feil(x) and x.bruker == h.bruker and x.ip == h.ip
                and timedelta(0) <= h.tid - x.tid <= timedelta(minutes=t["suksess_vindu_min"])]
        if len(feil) >= t["suksess_etter_feil"]:
            ut.append(Varsel("suksess_etter_feil",
                             f"«{h.bruker}» logget inn fra {h.ip} etter {len(feil)} feilede forsøk",
                             "høy", h.tid, h.kilde, "T1078", [h.bruker], [h.ip], [x.rå for x in feil[-2:]] + [h.rå]))
    return ut


def umulig_reise(hs: list[Hendelse]) -> list[Varsel]:
    ut, siste = [], {}
    for h in filter(lambda x: _ok(x) and x.land, hs):
        forrige = siste.get(h.bruker)
        if forrige and forrige.land != h.land and h.tid - forrige.tid <= timedelta(hours=TERSKLER["umulig_reise_timer"]):
            minutter = int((h.tid - forrige.tid).total_seconds() // 60)
            ut.append(Varsel("umulig_reise",
                             f"«{h.bruker}» logget inn fra {forrige.land} og {h.land} med {minutter} min mellomrom",
                             "høy", h.tid, h.kilde, "T1078", [h.bruker], [forrige.ip, h.ip], [forrige.rå, h.rå]))
        siste[h.bruker] = h
    return ut


def utenfor_arbeidstid(hs: list[Hendelse]) -> list[Varsel]:
    fra, til = TERSKLER["arbeidstid"]
    return [Varsel("utenfor_arbeidstid", f"Privilegert konto «{h.bruker}» logget inn kl. {h.tid:%H:%M}",
                   "lav", h.tid, h.kilde, "T1078.003", [h.bruker], [h.ip], [h.rå])
            for h in filter(_ok, hs) if h.bruker in PRIVILEGERTE and not fra <= h.tid.hour < til]


def phishing(hs: list[Hendelse]) -> list[Varsel]:
    return [Varsel("phishing", f"Mulig phishing til «{h.bruker}»: {h.detaljer['emne']}",
                   "middels", h.tid, "epost", "T1566.002", [h.bruker], [h.ip] if h.ip else [],
                   h.detaljer["funn"])
            for h in hs if h.type == "epost" and h.detaljer.get("poeng", 0) >= TERSKLER["phishing_poeng"]]


def bruker_kompromittert(hs: list[Hendelse]) -> list[Varsel]:
    return [Varsel("bruker_rapporterer_kompromittering",
                   f"«{h.bruker}» melder at hen har oppgitt passord på en lenke (sak {h.detaljer['id']})",
                   "høy", h.tid, "helpdesk", "T1566", [h.bruker], [], [h.rå])
            for h in hs if h.type == "sak" and KOMPROMITTERT.search(h.rå)]


def losepengevirus(hs: list[Hendelse]) -> list[Varsel]:
    return [Varsel("losepengevirus", f"Mulig løsepengevirus meldt av «{h.bruker}» (sak {h.detaljer['id']})",
                   "kritisk", h.tid, "helpdesk", "T1486", [h.bruker], [], [h.rå])
            for h in hs if h.type == "sak" and LOSEPENGER.search(h.rå)]


REGLER = [password_spraying, brute_force, suksess_etter_feil, umulig_reise, utenfor_arbeidstid,
          phishing, bruker_kompromittert, losepengevirus]


def kjor_regler(hs: list[Hendelse]) -> list[Varsel]:
    varsler = [v for regel in REGLER for v in regel(hs)]
    return sorted(varsler, key=lambda v: v.tid)
