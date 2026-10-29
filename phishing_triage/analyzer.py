"""Offline, non-executing analysis of RFC 5322 .eml messages: parse -> rules -> score."""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path

from .parse import MAX_EMAIL_BYTES, parse_bytes
from .rules import run_rules
from .scoring import score


def analyze_bytes(raw: bytes) -> dict:
    email = parse_bytes(raw)
    findings = run_rules(email)
    return {'sha256_email': email.sha256, 'headers': email.headers, 'links': email.links,
            'attachments': email.attachments, 'findings': [asdict(f) for f in findings], 'risk': score(findings),
            'analysis_notes': ['Offline static analysis only; no URLs visited or attachments executed.',
                               'Authentication-Results headers are unverified and may be forged; trusted '
                               'receiving-server context is required.',
                               'Domain comparisons use an approximate registrable-domain rule, not the full '
                               'Public Suffix List.',
                               'No threat intelligence or definitive maliciousness assessment in Phase 1.']}


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    return analyze_bytes(path.read_bytes())
