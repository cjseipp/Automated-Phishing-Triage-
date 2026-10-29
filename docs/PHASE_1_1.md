# Phase 1.1: URL deduplication and risk scoring

This package is a complete updated project. Extract into a **new folder** to keep your original Phase 1 as a backup.

Run from the folder containing `phishing_triage`:

```powershell
python -m unittest discover -s tests -v
python -m phishing_triage.cli samples/suspicious_login.eml --output reports/suspicious_login.json
notepad reports\suspicious_login.json
```

Risk weights: misleading displayed URL +50; different Reply-To +15. Score capped at 100; 1–29 low, 30–59 medium, 60–100 high; zero = no indicators detected (NOT safe). Each finding type is counted once. This is a preliminary heuristic, not a calibrated model.

URL entries are deduplicated by exact URL and retain `sources` and `display_texts`. The legacy `source` and `display_text` fields remain for compatibility. Distinct URL spellings may still refer to the same destination; HTML body extraction can include non-clickable URLs. No network requests or attachment execution.
