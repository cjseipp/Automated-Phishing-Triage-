import base64
import unittest
from pathlib import Path
from phishing_triage.analyzer import analyze_bytes, analyze_file
from phishing_triage.domains import is_ip_host, registrable_domain

ROOT = Path(__file__).resolve().parents[1]


def html_email(body, sender='alerts@bank.example'):
    return f'From: {sender}\nTo: user@nonprofit.example\nContent-Type: text/html\n\n{body}'.encode()


def text_email(body, sender='alerts@bank.example'):
    return f'From: {sender}\nTo: user@nonprofit.example\nContent-Type: text/plain\n\n{body}'.encode()


def attachment_email(filename, data=b'harmless demo content', content_type='application/octet-stream'):
    payload = base64.b64encode(data).decode()
    return (f'From: billing@vendor.example\nTo: accounts@nonprofit.example\nMIME-Version: 1.0\n'
            f'Content-Type: multipart/mixed; boundary="B"\n\n'
            f'--B\nContent-Type: text/plain\n\nSee attached.\n'
            f'--B\nContent-Type: {content_type}\nContent-Transfer-Encoding: base64\n'
            f'Content-Disposition: attachment; filename="{filename}"\n\n{payload}\n--B--\n').encode('utf-8')


def finding_types(raw):
    return {f['type'] for f in analyze_bytes(raw)['findings']}


class DomainTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain('www.mail.paypal.com'), 'paypal.com')
        self.assertEqual(registrable_domain('login.bank.co.uk'), 'bank.co.uk')
        self.assertEqual(registrable_domain('192.0.2.10'), '192.0.2.10')

    def test_ip_forms(self):
        for host in ('192.0.2.10', '::1', '3232235777', '0x7f000001'):
            self.assertTrue(is_ip_host(host), host)
        self.assertFalse(is_ip_host('example.com'))


class LinkRuleTests(unittest.TestCase):
    def test_display_mismatch_ignores_subdomain_difference(self):
        raw = html_email('<a href="https://www.paypal.com/x">https://paypal.com/x</a>', sender='a@paypal.com')
        self.assertNotIn('display_url_mismatch', finding_types(raw))

    def test_display_mismatch_without_scheme(self):
        raw = html_email('<a href="https://evil.example/login">microsoft.com</a>')
        self.assertIn('display_url_mismatch', finding_types(raw))

    def test_ip_address_link(self):
        self.assertIn('ip_address_link', finding_types(text_email('Log in at http://192.0.2.10/owa')))

    def test_punycode_link(self):
        self.assertIn('punycode_link', finding_types(text_email('Visit https://xn--pypal-4ve.example/')))

    def test_credentials_in_url(self):
        raw = html_email('<a href="https://bank.example@evil.example/login">Sign in</a>')
        self.assertIn('credentials_in_url', finding_types(raw))

    def test_url_shortener(self):
        self.assertIn('url_shortener', finding_types(text_email('Details: https://bit.ly/3abc')))

    def test_link_domain_mismatch_and_same_domain(self):
        self.assertIn('link_domain_mismatch', finding_types(text_email('https://other.example/x')))
        self.assertNotIn('link_domain_mismatch', finding_types(text_email('https://www.bank.example/x')))

    def test_image_and_script_urls_are_not_links(self):
        raw = html_email('<img src="https://cdn.example/logo.png"><script>var u="https://s.example/a.js"</script>'
                         '<p>Hello</p>')
        self.assertEqual(analyze_bytes(raw)['links'], [])


class AttachmentRuleTests(unittest.TestCase):
    def test_html_attachment_is_risky(self):
        self.assertIn('risky_attachment', finding_types(attachment_email('invoice.htm')))

    def test_archive(self):
        self.assertIn('archive_attachment', finding_types(attachment_email('docs.zip', b'PK\x03\x04demo')))

    def test_double_extension(self):
        kinds = finding_types(attachment_email('invoice.pdf.exe', b'MZ demo'))
        self.assertIn('double_extension', kinds)
        self.assertIn('risky_attachment', kinds)

    def test_rtlo_filename(self):
        self.assertIn('filename_obfuscation', finding_types(attachment_email('invoice‮fdp.exe')))

    def test_disguised_executable(self):
        report = analyze_bytes(attachment_email('statement.pdf', b'MZ\x90\x00 demo bytes'))
        kinds = {f['type'] for f in report['findings']}
        self.assertIn('disguised_executable', kinds)
        self.assertNotIn('attachment_type_mismatch', kinds)
        self.assertEqual(report['risk']['severity'], 'high')

    def test_type_mismatch(self):
        self.assertIn('attachment_type_mismatch', finding_types(attachment_email('report.pdf', b'not a pdf')))

    def test_real_pdf_not_flagged(self):
        self.assertEqual(finding_types(attachment_email('report.pdf', b'%PDF-1.7 demo')), set())


class SampleTests(unittest.TestCase):
    def test_html_attachment_lure_sample(self):
        report = analyze_file(ROOT / 'samples/html_attachment_lure.eml')
        kinds = {f['type'] for f in report['findings']}
        self.assertTrue({'risky_attachment', 'url_shortener'} <= kinds, kinds)
        self.assertEqual(report['risk']['severity'], 'high')


if __name__ == '__main__':
    unittest.main()
