"""Maskerer personopplysninger før tekst sendes til en KI-modell (dataminimering, GDPR art. 5)."""
from __future__ import annotations

import re

MONSTRE = [
    ("FØDSELSNUMMER", re.compile(r"\b[0-3]\d[01]\d\d{2}\s?\d{5}\b")),
    ("KORTNUMMER", re.compile(r"\b(?:\d[ -]?){15,16}\b")),
    ("PASSORD", re.compile(r"(?i)(passord(?:et)?(?: mitt)?\s*(?:er|:|=)\s*)(\S+)")),
    ("TELEFON", re.compile(r"(?<!\d)(?<!\d\.)(?:\+47\s?)?[49]\d(?:\s?\d){6}(?!\d)(?!\.\d)")),
]


def masker(tekst: str) -> str:
    for navn, m in MONSTRE:
        tekst = m.sub((lambda x: x.group(1) + "[PASSORD]") if navn == "PASSORD" else f"[{navn}]", tekst)
    return tekst
