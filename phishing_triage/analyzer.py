"""Offline, non-executing analysis of RFC 5322 .eml messages."""
from __future__ import annotations
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 1_000_000

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.active = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            attrs = dict(attrs)
            self.active = {'url': attrs.get('href', ''), 'display_text': ''}

    def handle_data(self, data):
        if self.active is not None:
            self.active['display_text'] += data

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self.active is not None:
            self.links.append(self.active)
            self.active = None


def _domain(address):
    return address.rsplit('@', 1)[-1].lower() if '@' in address else ''


def _hostname(url):
    try:
        return (urlsplit(url).hostname or '').lower()
    except ValueError:
        return ''


def analyze_bytes(raw: bytes) -> dict:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_address = getaddresses([str(msg.get('From', ''))])
    reply_address = getaddresses([str(msg.get('Reply-To', ''))])
    sender = from_address[0][1] if from_address else ''
    reply_to = reply_address[0][1] if reply_address else ''
    headers = {
        'from': str(msg.get('From', '')),
        'sender_address': sender,
        'to': str(msg.get('To', '')),
        'subject': str(msg.get('Subject', '')),
        'reply_to': str(msg.get('Reply-To', '')),
        'date': str(msg.get('Date', '')),
        'received': [str(v) for v in msg.get_all('Received', [])],
        'authentication_results_unverified': [str(v) for v in msg.get_all('Authentication-Results', [])],
    }
    findings = []
    if reply_to and sender and reply_to.lower() != sender.lower():
        findings.append({'type': 'reply_to_mismatch', 'detail': 'Reply-To differs from From; may be legitimate.'})
    links, attachments = [], []
    parts = list(msg.walk())
    if len(parts) > MAX_PARTS:
        raise ValueError('Email exceeds MIME part count limit')
    for part in parts:
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True)
        if data is None:
            data = b''
        filename = part.get_filename()
        if filename is not None or part.get_content_disposition() == 'attachment':
            attachments.append({'filename': filename or '(unnamed)', 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'content_type': part.get_content_type()})
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            body = data.decode(charset, errors='replace')[:MAX_TEXT_CHARS]
        except LookupError:
            body = data.decode('utf-8', errors='replace')[:MAX_TEXT_CHARS]
        if part.get_content_type() == 'text/html':
            parser = LinkParser()
            parser.feed(body)
            for link in parser.links:
                url = link['url']
                if url.lower().startswith(('http://', 'https://')):
                    links.append({'url': url, 'display_text': link['display_text'].strip(), 'source': 'html_anchor'})
                    displayed = link['display_text'].strip()
                    if displayed.lower().startswith(('http://', 'https://')) and _hostname(displayed) != _hostname(url):
                        findings.append({'type': 'display_url_mismatch', 'detail': 'Visible URL hostname differs from hyperlink destination.'})
        for url in URL_RE.findall(body):
            links.append({'url': url.rstrip('.,);'), 'display_text': '', 'source': part.get_content_type()})
    unique = []
    seen = set()
    for link in links:
        key = (link['url'], link['source'])
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return {'sha256_email': hashlib.sha256(raw).hexdigest(), 'headers': headers, 'links': unique, 'attachments': attachments, 'findings': findings, 'analysis_notes': ['Offline static analysis only; no URLs visited or attachments executed.', 'Authentication-Results headers are unverified and may be forged; trusted receiving-server context is required.', 'No threat intelligence or definitive maliciousness assessment in Phase 1.']}


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    return analyze_bytes(path.read_bytes())
