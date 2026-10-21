import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishguard.analysis import analyze  # noqa: E402
from phishguard.parser import parse_email  # noqa: E402
from phishguard.samples import SAMPLES, write_samples  # noqa: E402
from phishguard.score import build_result, score  # noqa: E402


def result_for(eml):
    email = parse_email(eml)
    return build_result(email, analyze(email))


class ParserTests(unittest.TestCase):
    def test_parse_from_and_domain(self):
        e = parse_email(SAMPLES["phishing_banco.eml"])
        self.assertEqual(e["from_domain"], "bradesco-alertas.xyz")
        self.assertTrue(e["has_html"])
        self.assertTrue(e["urls"])

    def test_parse_attachment(self):
        e = parse_email(SAMPLES["phishing_anexo.eml"])
        self.assertEqual(len(e["attachments"]), 1)
        self.assertTrue(e["attachments"][0]["double_ext"])

    def test_link_text_vs_href(self):
        e = parse_email(SAMPLES["phishing_banco.eml"])
        # texto mostra bradesco.com.br mas href vai para IP
        self.assertTrue(any("191.101" in href for _, href in e["links"]))


class DetectionTests(unittest.TestCase):
    def test_phishing_scores_high(self):
        self.assertGreaterEqual(result_for(SAMPLES["phishing_banco.eml"])["score"], 70)
        self.assertGreaterEqual(result_for(SAMPLES["phishing_anexo.eml"])["score"], 70)

    def test_legit_scores_low(self):
        self.assertEqual(result_for(SAMPLES["legitimo_github.eml"])["score"], 0)
        self.assertLess(result_for(SAMPLES["legitimo_newsletter.eml"])["score"], 18)

    def test_dmarc_fail_detected(self):
        checks = {f["check"] for f in result_for(SAMPLES["phishing_banco.eml"])["findings"]}
        self.assertIn("auth", checks)

    def test_dangerous_attachment_is_critical(self):
        r = result_for(SAMPLES["phishing_anexo.eml"])
        self.assertEqual(r["level"], "critical")
        self.assertTrue(any(f["check"] == "attachment" and f["severity"] == "critical" for f in r["findings"]))

    def test_ip_url_detected(self):
        titles = [f["title"] for f in result_for(SAMPLES["phishing_banco.eml"])["findings"]]
        self.assertTrue(any("IP" in t for t in titles))

    def test_score_bounds(self):
        self.assertLessEqual(score([type("F", (), {"weight": 999, "severity": "high"})()])["score"], 100)


class SampleTests(unittest.TestCase):
    def test_write_samples(self):
        with tempfile.TemporaryDirectory() as d:
            created = write_samples(d)
            self.assertEqual(len(created), 4)
            for p in created:
                self.assertTrue(os.path.getsize(p) > 50)


if __name__ == "__main__":
    unittest.main()
