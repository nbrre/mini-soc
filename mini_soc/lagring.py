"""Lagring i SQLite (innebygd i Python). Har også en revisjonslogg over alt agenten gjør."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from .korrelasjon import Sak
from .modeller import Hendelse

SKJEMA = """
CREATE TABLE IF NOT EXISTS hendelser (id INTEGER PRIMARY KEY, tid TEXT, kilde TEXT, type TEXT,
    bruker TEXT, ip TEXT, land TEXT, detaljer TEXT, raa TEXT);
CREATE INDEX IF NOT EXISTS ix_h_bruker ON hendelser(bruker);
CREATE INDEX IF NOT EXISTS ix_h_ip ON hendelser(ip);
CREATE TABLE IF NOT EXISTS saker (id INTEGER PRIMARY KEY, alvor TEXT, status TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS notater (id INTEGER PRIMARY KEY, sak_id INTEGER, tid TEXT, forfatter TEXT, tekst TEXT);
CREATE TABLE IF NOT EXISTS revisjon (id INTEGER PRIMARY KEY, tid TEXT, aktor TEXT, handling TEXT, detaljer TEXT);
"""


class Lager:
    def __init__(self, sti: str = ":memory:"):
        self.db = sqlite3.connect(sti, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SKJEMA)

    # --- skriving ---
    def lagre_hendelser(self, hs: list[Hendelse]) -> None:
        self.db.executemany(
            "INSERT INTO hendelser (tid, kilde, type, bruker, ip, land, detaljer, raa) VALUES (?,?,?,?,?,?,?,?)",
            [(h.tid.isoformat(timespec="seconds"), h.kilde, h.type, h.bruker, h.ip, h.land,
              json.dumps(h.detaljer, ensure_ascii=False), h.rå) for h in hs])
        self.db.commit()

    def lagre_saker(self, saker: list[Sak]) -> None:
        for s in saker:
            cur = self.db.execute("INSERT INTO saker (alvor, status, data) VALUES (?,?,?)",
                                  (s.alvor, s.status, "{}"))
            s.id = cur.lastrowid
            self.oppdater_sak(s.id, s.til_dict())
        self.logg("system", "saker_opprettet", {"antall": len(saker)})

    def oppdater_sak(self, sak_id: int, data: dict) -> None:
        data["id"] = sak_id
        self.db.execute("UPDATE saker SET alvor=?, status=?, data=? WHERE id=?",
                        (data["alvor"], data["status"], json.dumps(data, ensure_ascii=False), sak_id))
        self.db.commit()

    def legg_til_notat(self, sak_id: int, tekst: str, forfatter: str = "agent") -> None:
        self.db.execute("INSERT INTO notater (sak_id, tid, forfatter, tekst) VALUES (?,?,?,?)",
                        (sak_id, datetime.now().isoformat(timespec="seconds"), forfatter, tekst))
        self.db.commit()

    def logg(self, aktor: str, handling: str, detaljer: dict) -> None:
        self.db.execute("INSERT INTO revisjon (tid, aktor, handling, detaljer) VALUES (?,?,?,?)",
                        (datetime.now().isoformat(timespec="seconds"), aktor, handling,
                         json.dumps(detaljer, ensure_ascii=False)))
        self.db.commit()

    # --- lesing ---
    def saker(self) -> list[dict]:
        return [json.loads(r["data"]) for r in self.db.execute("SELECT data FROM saker ORDER BY id")]

    def sak(self, sak_id: int) -> dict | None:
        r = self.db.execute("SELECT data FROM saker WHERE id=?", (sak_id,)).fetchone()
        return json.loads(r["data"]) if r else None

    def notater(self, sak_id: int) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT tid, forfatter, tekst FROM notater WHERE sak_id=? ORDER BY id",
                                                 (sak_id,))]

    def sok_hendelser(self, bruker: str = "", ip: str = "", fra: str = "", til: str = "", maks: int = 50) -> list[dict]:
        sql, arg = "SELECT tid, kilde, type, bruker, ip, land, raa FROM hendelser WHERE 1=1", []
        for kol, verdi, op in (("bruker", bruker, "="), ("ip", ip, "="), ("tid", fra, ">="), ("tid", til, "<=")):
            if verdi:
                sql += f" AND {kol} {op} ?"
                arg.append(verdi)
        sql += " ORDER BY tid LIMIT ?"
        return [dict(r) for r in self.db.execute(sql, (*arg, maks))]

    def revisjonslogg(self, maks: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT tid, aktor, handling, detaljer FROM revisjon ORDER BY id DESC LIMIT ?",
                                                 (maks,))]
