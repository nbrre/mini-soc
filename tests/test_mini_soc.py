import json
import pathlib
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

from mini_soc import agent
from mini_soc.api import lag_handler
from mini_soc.evaluering import evaluer_alle
from mini_soc.kilder import les_mappe
from mini_soc.kilder.epost import vurder_phishing
from mini_soc.korrelasjon import korreler
from mini_soc.lagring import Lager
from mini_soc.personvern import masker
from mini_soc.pipeline import kjor
from mini_soc.regler import kjor_regler

ROT = pathlib.Path(__file__).resolve().parent.parent
EKS = ROT / "eksempler"


class TestKilderOgRegler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hendelser = les_mappe(EKS)
        cls.varsler = kjor_regler(cls.hendelser)
        cls.regler = {v.regel for v in cls.varsler}

    def test_leser_alle_kilder(self):
        self.assertEqual({h.kilde for h in self.hendelser}, {"ssh", "entra", "epost", "helpdesk"})

    def test_finner_alle_angrepstyper(self):
        for r in ("password_spraying", "brute_force", "suksess_etter_feil", "umulig_reise",
                  "utenfor_arbeidstid", "phishing", "bruker_rapporterer_kompromittering", "losepengevirus"):
            self.assertIn(r, self.regler)

    def test_varsler_har_mitre(self):
        self.assertTrue(all(v.mitre.startswith("T") for v in self.varsler))

    def test_vanlig_epost_er_ikke_phishing(self):
        poeng, _ = vurder_phishing("Kari <kari@firma.example>", "", "Kan vi ta budsjettmøtet torsdag?")
        self.assertLess(poeng, 6)

    def test_ekte_avsender_er_ikke_falsk(self):
        _, funn = vurder_phishing("DNB <info@dnb.no>", "", "Hei")
        self.assertFalse(any("utgir seg" in f for f in funn))


class TestKorrelasjon(unittest.TestCase):
    def setUp(self):
        self.saker = korreler(kjor_regler(les_mappe(EKS)))

    def test_angrepskjeden_blir_en_kritisk_sak(self):
        forste = self.saker[0]
        self.assertEqual(forste.alvor, "kritisk")
        self.assertEqual(forste.brukere, ["mia"])
        self.assertEqual(len(forste.varsler), 5)
        self.assertEqual(forste.faser, ["Første tilgang", "Bruk av gyldige kontoer", "Ødeleggelse/påvirkning"])

    def test_kontornett_kobler_ikke_saker(self):
        # admin og mia brukte begge 192.0.2.10 (kontoret), men skal ikke havne i samme sak
        for s in self.saker:
            self.assertFalse({"admin", "mia"} <= set(s.brukere))

    def test_fire_saker_sortert_etter_alvor(self):
        self.assertEqual([s.alvor for s in self.saker], ["kritisk", "høy", "middels", "lav"])


class TestPersonvern(unittest.TestCase):
    def test_maskerer(self):
        t = masker("Ring 912 34 567, fnr 01019912345, passordet er Hemmelig1. IP 203.0.113.99")
        for rå in ("912 34 567", "01019912345", "Hemmelig1"):
            self.assertNotIn(rå, t)
        self.assertIn("203.0.113.99", t)  # IP-er trengs til etterforskningen


class TestEval(unittest.TestCase):
    def test_full_treff_pa_fasit(self):
        for r in evaluer_alle(ROT / "eval"):
            self.assertEqual((r["presisjon"], r["gjenfinning"]), (1.0, 1.0), r)


def blokk(type_, **kw):
    return SimpleNamespace(type=type_, **kw)


class FalskClaude:
    """Spiller av et fast manus med verktøykall, slik at agent-løkken kan testes uten API-nøkkel."""

    def __init__(self, manus):
        self.manus, self.kall = list(manus), []
        self.messages = self

    def create(self, **kw):
        self.kall.append(kw)
        return SimpleNamespace(content=self.manus.pop(0), stop_reason="tool_use")


RAPPORT = {"oppsummering": "Mia ble lurt av phishing, angriperen logget inn og krypterte filer.", "alvor": "kritisk",
           "sikkerhet": 90, "tidslinje": [{"tid": "10:12", "hendelse": "Phishing mottatt"}], "berorte": ["mia"],
           "mitre": ["T1566.002", "T1078", "T1486"], "tiltak_na": ["Koble Mias PC fra nettet"], "varsling": "Datatilsynet innen 72 timer."}


class TestAgent(unittest.TestCase):
    def setUp(self):
        self.lager = kjor(EKS)

    def test_agent_loekke_med_verktoy_minne_og_revisjon(self):
        klient = FalskClaude([
            [blokk("text", text="Jeg starter."), blokk("tool_use", id="1", name="hent_sak", input={"sak_id": 1})],
            [blokk("tool_use", id="2", name="sok_hendelser", input={"bruker": "mia"}),
             blokk("tool_use", id="3", name="sla_opp_ip", input={"ip": "203.0.113.99"})],
            [blokk("tool_use", id="4", name="skriv_notat", input={"sak_id": 1, "tekst": "IP er kjent phishing-server."})],
            [blokk("tool_use", id="5", name="lever_rapport", input=RAPPORT)],
        ])
        rapport = agent.etterforsk(1, self.lager, klient=klient, vis=lambda *_: None)
        self.assertEqual(rapport["alvor"], "kritisk")
        self.assertEqual(self.lager.sak(1)["status"], "etterforsket")
        self.assertEqual(self.lager.notater(1)[0]["tekst"], "IP er kjent phishing-server.")
        handlinger = [r["handling"] for r in self.lager.revisjonslogg()]
        for h in ("start", "hent_sak", "sok_hendelser", "sla_opp_ip", "skriv_notat", "rapport"):
            self.assertIn(h, handlinger)

        # Verktøysvarene som gikk til modellen: maskert telefonnummer, logger merket som data, trusselinfo med
        sendt = json.dumps([m["content"] for m in klient.kall[-1]["messages"] if m["role"] == "user"], ensure_ascii=False, default=str)
        self.assertNotIn("912 34 567", sendt)
        self.assertIn("<data>", sendt)
        self.assertIn("phishing", sendt)

    def test_siste_steg_tvinger_rapport(self):
        manus = [[blokk("tool_use", id=str(i), name="les_notater", input={"sak_id": 1})] for i in range(2)]
        manus.append([blokk("tool_use", id="r", name="lever_rapport", input=RAPPORT)])
        klient = FalskClaude(manus)
        agent.etterforsk(1, self.lager, klient=klient, maks_steg=3, vis=lambda *_: None)
        self.assertEqual(klient.kall[-1]["tool_choice"], {"type": "tool", "name": "lever_rapport"})

    def test_ukjent_verktoy_gir_feilmelding(self):
        v = agent.Verktoy(self.lager)
        self.assertIn("feil", v.kjor("slett_alt", {}))
        self.assertIn("feil", v.kjor("lever_rapport", {}))


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), lag_handler(kjor(EKS)))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def hent(self, sti):
        with urllib.request.urlopen(self.url + sti) as r:
            return r.status, r.headers, r.read()

    def test_saker(self):
        status, _, kropp = self.hent("/api/saker")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(kropp)), 4)

    def test_dashboard_med_sikkerhetsheadere(self):
        status, headere, kropp = self.hent("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Mini-SOC", kropp)
        self.assertIn("default-src 'self'", headere["Content-Security-Policy"])

    def test_ukjent_sti_gir_404(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.hent("/api/finnes-ikke")
        self.assertEqual(e.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
