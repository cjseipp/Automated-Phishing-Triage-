# Phase 1.2: Rule engine, link and attachment detection

## Restructure

The single `analyzer.py` is split into a pipeline:

| Module | Role |
|---|---|
| `parse.py` | Turns `.eml` bytes into a `ParsedEmail` (headers, deduplicated links, attachments). Nothing is fetched or executed. |
| `domains.py` | Hostname, IP and registrable-domain helpers (`www.mail.paypal.com` → `paypal.com`). |
| `rules.py` | One function per indicator, registered with `@rule`. Each returns a `Finding` with evidence, or `None`. |
| `scoring.py` | `WEIGHTS` table and severity bands. Tune points here without touching rule code. |
| `analyzer.py` | `analyze_bytes` / `analyze_file`: parse → run rules → score. Report format is unchanged apart from additions. |

To add a rule: write a function in `rules.py` decorated with `@rule`, add its weight to `scoring.WEIGHTS`, and add a test in `tests/test_rules.py`.

## Rules and weights (`heuristic_v2`)

| Rule | Points | Fires when |
|---|---|---|
| `display_url_mismatch` | 50 | Link text names a different domain than the destination (now compares registrable domains, so `www.` differences no longer flag; also catches text like `microsoft.com` without `https://`) |
| `reply_to_mismatch` | 15 | Reply-To **domain** differs from From domain (previously any address difference) |
| `credentials_in_url` | 40 | `https://bank.example@evil.example` style links |
| `ip_address_link` | 40 | Link host is an IP, including decimal/hex forms |
| `punycode_link` | 30 | `xn--` or non-ASCII host |
| `url_shortener` | 20 | bit.ly, tinyurl.com, t.co and similar |
| `link_domain_mismatch` | 10 | Links go to domains other than the sender's (low weight: normal in newsletters) |
| `disguised_executable` | 60 | File starts with an executable header but is not named as one |
| `risky_attachment` | 40 | `.htm/.html`, `.svg`, scripts, `.lnk`, `.iso/.img`, `.one`, macro documents, executables |
| `double_extension` | 40 | `invoice.pdf.exe` |
| `filename_obfuscation` | 40 | Hidden right-to-left override characters or padding before the extension |
| `attachment_type_mismatch` | 25 | e.g. `.pdf` that is not a PDF |
| `archive_attachment` | 15 | `.zip`, `.rar`, `.7z` and similar |

Each rule type counts once. Score capped at 100; 1–29 low, 30–59 medium, 60–100 high; 0 = no indicators detected (not "safe"). Weights are still hand-set, not calibrated against data.

## Other changes

- HTML link extraction only records `<a href>` links and URLs in visible text. `<img src>`, script and style URLs are no longer reported as links.
- Link entries add `hostname` and `registrable_domain`; attachments add `detected_type` (from file signature).
- Findings add an `evidence` list.
- `samples/html_attachment_lure.eml`: harmless demo of an HTML-attachment payroll lure.
- 24 tests (was 6).

## Known gaps (next steps)

- Sender checks: email address in display name, lookalike domains.
- SPF/DKIM/DMARC from a trusted `Authentication-Results` server ID.
- Urgency / credential wording.
- An evaluation corpus to measure detection and false-positive rates and tune weights.
- Registrable-domain logic is approximate (no full Public Suffix List).
