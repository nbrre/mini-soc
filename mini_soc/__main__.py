"""Kommandolinje.

  python -m mini_soc analyser eksempler          # les data, finn varsler og saker
  python -m mini_soc etterforsk eksempler --sak 1 # la KI-agenten etterforske en sak
  python -m mini_soc server eksempler            # start dashboard på http://127.0.0.1:8000
  python -m mini_soc eval                        # mål treffsikkerhet mot fasit i eval/
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .pipeline import kjor

FARGE = {"kritisk": "\033[41;97m", "høy": "\033[31m", "middels": "\033[33m", "lav": "\033[32m"}
NULL = "\033[0m"


def vis_saker(lager) -> None:
    saker = lager.saker()
    print(f"{len(saker)} saker (viktigste først):\n")
    for s in saker:
        print(f"{FARGE[s['alvor']]}[{s['alvor'].upper():^8}]{NULL} Sak {s['id']}: {s['tittel']}")
        print(f"           Faser: {' → '.join(s['faser'])}")
        for v in s["varsler"]:
            print(f"           {v['tid'][11:16]}  {v['mitre']:<10} {v['tittel']}")
        print()


def vis_rapport(r: dict) -> None:
    print(f"\n{'=' * 70}\nHENDELSESRAPPORT – alvor: {r['alvor'].upper()} ({r['sikkerhet']} % sikker)\n{'=' * 70}")
    print(r["oppsummering"], "\n\nTidslinje:")
    for t in r["tidslinje"]:
        print(f"  {t['tid']}  {t['hendelse']}")
    print("\nStrakstiltak:")
    for i, t in enumerate(r["tiltak_na"], 1):
        print(f"  {i}. {t}")
    if r.get("tiltak_senere"):
        print("\nSenere:")
        for t in r["tiltak_senere"]:
            print(f"  • {t}")
    print(f"\nVarsling: {r['varsling']}\nMITRE ATT&CK: {', '.join(r['mitre'])}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mini_soc", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    under = p.add_subparsers(dest="kommando", required=True)
    for navn in ("analyser", "etterforsk", "server"):
        u = under.add_parser(navn)
        u.add_argument("mappe", help="Mappe med logger, CSV, helpdesk.json og eposter/")
        u.add_argument("--db", default=":memory:", help="SQLite-fil (standard: bare i minnet)")
        if navn == "etterforsk":
            u.add_argument("--sak", type=int, default=1)
        if navn == "server":
            u.add_argument("--vert", default=os.getenv("SOC_VERT", "127.0.0.1"))
            u.add_argument("--port", type=int, default=int(os.getenv("SOC_PORT", "8000")))
    e = under.add_parser("eval")
    e.add_argument("mappe", nargs="?", default="eval")
    a = p.parse_args(argv)

    if a.kommando == "eval":
        from .evaluering import evaluer_alle
        resultater = evaluer_alle(a.mappe)
        for r in resultater:
            print(f"{r['scenario']:<15} presisjon {r['presisjon']:.2f}  gjenfinning {r['gjenfinning']:.2f}  "
                  f"({r['riktige']}/{r['forventet']} riktige saker, {r['funnet']} funnet)")
            for m in r["mangler"]:
                print(f"   mangler: {m}")
            for x in r["ekstra"]:
                print(f"   ekstra:  {x}")
        return 0 if all(r["presisjon"] == r["gjenfinning"] == 1.0 for r in resultater) else 1

    lager = kjor(a.mappe, __import__("mini_soc.lagring", fromlist=["Lager"]).Lager(a.db))
    if a.kommando == "analyser":
        vis_saker(lager)
    elif a.kommando == "server":
        from .api import start
        start(lager, a.vert, a.port)
    elif a.kommando == "etterforsk":
        if not os.getenv("ANTHROPIC_API_KEY"):
            print("Sett ANTHROPIC_API_KEY for å bruke KI-agenten (se README).", file=sys.stderr)
            return 2
        from .agent import etterforsk
        print(f"Agenten etterforsker sak {a.sak} …")
        vis_rapport(etterforsk(a.sak, lager))
        print("\nRevisjonslogg (siste handlinger):")
        for r in reversed(lager.revisjonslogg(15)):
            print(f"  {r['tid']}  {r['aktor']:<6} {r['handling']:<14} {json.loads(r['detaljer'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
