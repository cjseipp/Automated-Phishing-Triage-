import unittest
from pathlib import Path
from phishing_triage.analyzer import analyze_file, analyze_bytes

ROOT = Path(__file__).resolve().parents[1]
class AnalyzerTests(unittest.TestCase):
    def test_suspicious(self):
        report = analyze_file(ROOT / 'samples/suspicious_login.eml')
        kinds = {item['type'] for item in report['findings']}
        self.assertIn('reply_to_mismatch', kinds)
        self.assertIn('display_url_mismatch', kinds)
    def test_legitimate(self):
        report = analyze_file(ROOT / 'samples/legitimate_notice.eml')
        self.assertFalse(report['findings'])
    def test_attachment(self):
        report = analyze_file(ROOT / 'samples/invoice_attachment.eml')
        self.assertEqual(len(report['attachments']), 1)
        self.assertEqual(len(report['attachments'][0]['sha256']), 64)
    def test_url_dedup_and_risk(self):
        report = analyze_file(ROOT / 'samples/suspicious_login.eml')
        urls = [link['url'] for link in report['links']]
        self.assertEqual(len(urls), len(set(urls)))
        self.assertEqual(len(urls), 2)
        # display_url_mismatch 50 + reply_to_mismatch 15 + link_domain_mismatch 10
        self.assertEqual(report['risk']['score'], 75)
        self.assertEqual(report['risk']['severity'], 'high')
        self.assertEqual(len(report['risk']['contributions']), 3)
    def test_clean_is_not_proven_safe(self):
        report = analyze_file(ROOT / 'samples/legitimate_notice.eml')
        self.assertEqual(report['risk']['score'], 0)
        self.assertEqual(report['risk']['severity'], 'no_indicators_detected')
    def test_limit(self):
        with self.assertRaises(ValueError):
            analyze_bytes(b'x' * (10 * 1024 * 1024 + 1))

if __name__ == '__main__':
    unittest.main()
