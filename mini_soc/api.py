"""Enkelt HTTP-API og dashboard (bare Python-standardbiblioteket).

GET  /                       dashboard
GET  /api/saker              alle saker
GET  /api/saker/<id>         én sak med notater
POST /api/saker/<id>/etterforsk   kjør KI-agenten (krever ANTHROPIC_API_KEY)
GET  /api/revisjon           revisjonslogg
"""
from __future__ import annotations

import json
import os
import pathlib
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .lagring import Lager

STATIC = pathlib.Path(__file__).resolve().parent / "static"


def lag_handler(lager: Lager):
    class Handler(BaseHTTPRequestHandler):
        def _svar(self, status: int, data, type_="application/json; charset=utf-8"):
            kropp = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", type_)
            self.send_header("Content-Length", str(len(kropp)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(kropp)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._svar(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            if self.path == "/app.js":
                return self._svar(200, (STATIC / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            if self.path == "/api/saker":
                return self._svar(200, lager.saker())
            if self.path == "/api/revisjon":
                return self._svar(200, lager.revisjonslogg())
            if m := re.fullmatch(r"/api/saker/(\d+)", self.path):
                sak = lager.sak(int(m[1]))
                return self._svar(200, {**sak, "notater": lager.notater(sak["id"])}) if sak else self._svar(404, {"feil": "finnes ikke"})
            self._svar(404, {"feil": "finnes ikke"})

        def do_POST(self):
            if m := re.fullmatch(r"/api/saker/(\d+)/etterforsk", self.path):
                if not os.getenv("ANTHROPIC_API_KEY"):
                    return self._svar(400, {"feil": "ANTHROPIC_API_KEY er ikke satt"})
                from .agent import etterforsk
                try:
                    return self._svar(200, etterforsk(int(m[1]), lager, vis=lambda *_: None))
                except Exception as e:  # noqa: BLE001 – vis feilen i dashboardet
                    return self._svar(500, {"feil": str(e)})
            self._svar(404, {"feil": "finnes ikke"})

        def log_message(self, *args):  # stille i terminalen
            pass

    return Handler


def start(lager: Lager, vert: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((vert, port), lag_handler(lager))
    print(f"Dashboard: http://{vert}:{port}  (Ctrl+C for å stoppe)")
    server.serve_forever()
