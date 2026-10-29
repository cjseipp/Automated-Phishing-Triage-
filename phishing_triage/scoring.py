"""Explainable additive risk score. Weights are preliminary heuristics, not a calibrated model."""
from __future__ import annotations

METHOD = 'heuristic_v2'

WEIGHTS = {
    # Headers
    'reply_to_mismatch': 15,
    # Links
    'display_url_mismatch': 50,
    'credentials_in_url': 40,
    'ip_address_link': 40,
    'punycode_link': 30,
    'url_shortener': 20,
    'link_domain_mismatch': 10,
    # Attachments
    'disguised_executable': 60,
    'risky_attachment': 40,
    'double_extension': 40,
    'filename_obfuscation': 40,
    'attachment_type_mismatch': 25,
    'archive_attachment': 15,
}


def severity_for(score: int) -> str:
    if score >= 60:
        return 'high'
    if score >= 30:
        return 'medium'
    return 'low' if score > 0 else 'no_indicators_detected'


def score(findings: list) -> dict:
    # Each finding type is counted once, however much evidence it has.
    contributions = [{'type': f.type, 'points': WEIGHTS.get(f.type, 0), 'reason': f.detail} for f in findings]
    total = min(100, sum(c['points'] for c in contributions))
    return {'score': total, 'severity': severity_for(total), 'contributions': contributions, 'method': METHOD,
            'note': 'Triage priority only; not probability of maliciousness or a clean verdict.'}
