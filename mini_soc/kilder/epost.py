"""E-post (.eml). Gir en epost-hendelse per melding med en enkel phishing-vurdering."""
from __future__ import annotations

import pathlib
import re
from email import message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

from ..modeller import Hendelse

MERKER = ["dnb", "posten", "nav", "skatteetaten", "vipps", "microsoft", "bring"]
HASTE = ["innen 24 timer", "stengt", "suspendert", "haster", "umiddelbart", "siste varsel"]
SENSITIVT = ["passord", "bankid", "kortnummer", "logg inn", "bekreft"]
RISIKO_TLD = (".xyz", ".top", ".click", ".zip", ".ru", ".tk")
URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _domene(adr: str) -> str:
    return adr.rsplit("@", 1)[-1].lower() if "@" in adr else ""


def vurder_phishing(fra: str, svar_til: str, tekst: str) -> tuple[int, list[str]]:
    navn, adr = parseaddr(fra)
    dom, lav, funn = _domene(adr), tekst.lower(), []
    if any(o in lav for o in HASTE):
        funn.append(("hastverk", 2))
    if any(o in lav for o in SENSITIVT):
        funn.append(("ber om innlogging/passord", 3))
    if svar_til and _domene(parseaddr(svar_til)[1]) not in ("", dom):
        funn.append(("svar-adresse til annet domene", 2))
    for m in MERKER:
        if m in navn.lower() and not (dom == f"{m}.no" or dom.endswith(f".{m}.no") or dom == f"{m}.com"):
            funn.append((f"utgir seg for å være {m.upper()} fra {dom}", 3))
            break
    for url in URL.findall(tekst):
        vert = (urlparse(url).hostname or "").lower()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", vert):
            funn.append((f"lenke til IP-adresse {vert}", 3))
        elif vert.endswith(RISIKO_TLD):
            funn.append((f"lenke til risikabelt domene {vert}", 2))
    return sum(p for _, p in funn), [f for f, _ in funn]


def les_eposter(mappe: str | pathlib.Path) -> list[Hendelse]:
    ut = []
    for fil in sorted(pathlib.Path(mappe).glob("*.eml")):
        msg = message_from_string(fil.read_text(encoding="utf-8"))
        tekst = msg.get_payload() if not msg.is_multipart() else "\n".join(
            str(d.get_payload()) for d in msg.walk() if d.get_content_maintype() == "text")
        poeng, funn = vurder_phishing(msg.get("From", ""), msg.get("Reply-To", ""), f"{msg.get('Subject', '')}\n{tekst}")
        lenker = [urlparse(u).hostname for u in URL.findall(tekst)]
        ips = [v for v in lenker if v and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v)]
        ut.append(Hendelse(parsedate_to_datetime(msg["Date"]).replace(tzinfo=None), "epost", "epost",
                           bruker=parseaddr(msg.get("To", ""))[1].split("@")[0].lower(), ip=ips[0] if ips else "",
                           detaljer={"fra": msg.get("From", ""), "emne": msg.get("Subject", ""), "poeng": poeng,
                                     "funn": funn, "lenker": lenker, "fil": fil.name},
                           rå=f"Fra: {msg.get('From')}\nEmne: {msg.get('Subject')}\n\n{tekst.strip()}"))
    return ut
