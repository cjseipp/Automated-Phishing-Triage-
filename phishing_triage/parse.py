"""Parse RFC 5322 .eml bytes into plain data. Nothing is fetched, rendered or executed."""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser

from .domains import email_domain, hostname, registrable_domain

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 1_000_000

# Leading bytes of common file formats, used to spot attachments whose
# extension lies about their contents.
_MAGIC = [
    (b'MZ', 'windows_executable'),
    (b'\x7fELF', 'elf_executable'),
    (b'%PDF-', 'pdf'),
    (b'PK\x03\x04', 'zip_container'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole_compound'),
    (b'Rar!\x1a\x07', 'rar'),
    (b"7z\xbc\xaf'\x1c", '7z'),
    (b'L\x00\x00\x00\x01\x14\x02\x00', 'windows_shortcut'),
]


@dataclass
class ParsedEmail:
    sha256: str
    headers: dict
    sender: str
    reply_to: str
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)

    @property
    def sender_domain(self) -> str:
        return email_domain(self.sender)


class _HTMLScanner(HTMLParser):
    """Collects <a href> links and visible text; script and style content is ignored."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self._active = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ('script', 'style'):
            self._skip += 1
        elif tag == 'a':
            self._finish_link()
            self._active = {'url': dict(attrs).get('href') or '', 'display_text': ''}

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1
        elif tag == 'a':
            self._finish_link()

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._active is not None:
            self._active['display_text'] += data

    def _finish_link(self):
        if self._active is not None:
            self.links.append(self._active)
            self._active = None

    def close(self):
        super().close()
        self._finish_link()


def detect_file_type(data: bytes) -> str | None:
    for signature, kind in _MAGIC:
        if data.startswith(signature):
            return kind
    if data[0x8001:0x8006] == b'CD001':
        return 'iso_image'
    return None


def _extract_links(body: str, content_type: str) -> list:
    """Clickable links only: <a href> in HTML, plus URLs written out in visible or plain text."""
    links = []
    if content_type == 'text/html':
        scanner = _HTMLScanner()
        scanner.feed(body)
        scanner.close()
        for link in scanner.links:
            url = link['url'].strip()
            if url.lower().startswith(('http://', 'https://')):
                links.append({'url': url, 'display_text': link['display_text'].strip(), 'source': 'html_anchor'})
        text = ' '.join(scanner.text)
    else:
        text = body
    for url in URL_RE.findall(text):
        links.append({'url': url.rstrip('.,);'), 'display_text': '', 'source': content_type})
    return links


def _dedupe_links(links: list) -> list:
    # One entry per exact destination URL, retaining all observed contexts.
    unique_by_url = {}
    for link in links:
        url = link['url']
        if url not in unique_by_url:
            host = hostname(url)
            unique_by_url[url] = {'url': url, 'display_text': link['display_text'], 'source': link['source'],
                                  'sources': [], 'display_texts': [],
                                  'hostname': host, 'registrable_domain': registrable_domain(host)}
        entry = unique_by_url[url]
        if link['source'] not in entry['sources']:
            entry['sources'].append(link['source'])
        if link['display_text'] and link['display_text'] not in entry['display_texts']:
            entry['display_texts'].append(link['display_text'])
    return list(unique_by_url.values())


def parse_bytes(raw: bytes) -> ParsedEmail:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_address = getaddresses([str(msg.get('From', ''))])
    reply_address = getaddresses([str(msg.get('Reply-To', ''))])
    headers = {
        'from': str(msg.get('From', '')),
        'sender_address': from_address[0][1] if from_address else '',
        'to': str(msg.get('To', '')),
        'subject': str(msg.get('Subject', '')),
        'reply_to': str(msg.get('Reply-To', '')),
        'date': str(msg.get('Date', '')),
        'received': [str(v) for v in msg.get_all('Received', [])],
        'authentication_results_unverified': [str(v) for v in msg.get_all('Authentication-Results', [])],
    }
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
            attachments.append({'filename': filename or '(unnamed)', 'size_bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest(),
                                'content_type': part.get_content_type(),
                                'detected_type': detect_file_type(data)})
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            body = data.decode(charset, errors='replace')[:MAX_TEXT_CHARS]
        except LookupError:
            body = data.decode('utf-8', errors='replace')[:MAX_TEXT_CHARS]
        links.extend(_extract_links(body, part.get_content_type()))
    return ParsedEmail(sha256=hashlib.sha256(raw).hexdigest(), headers=headers,
                       sender=headers['sender_address'], reply_to=reply_address[0][1] if reply_address else '',
                       links=_dedupe_links(links), attachments=attachments)
