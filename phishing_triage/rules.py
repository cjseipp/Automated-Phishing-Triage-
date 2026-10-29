"""Local detection rules.

Each rule takes a ParsedEmail and returns one Finding (with every piece of
supporting evidence) or None. Points live in scoring.WEIGHTS, not here.
Register a new rule with the @rule decorator.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .domains import email_domain, hostname, is_ip_host, registrable_domain
from .parse import ParsedEmail


@dataclass
class Finding:
    type: str
    detail: str
    evidence: list = field(default_factory=list)


RULES = []


def rule(fn):
    RULES.append(fn)
    return fn


def run_rules(email: ParsedEmail) -> list:
    return [finding for check in RULES if (finding := check(email))]


# --- Headers ---------------------------------------------------------------

@rule
def reply_to_mismatch(email):
    if email.reply_to and email.sender and email_domain(email.reply_to) != email_domain(email.sender):
        return Finding('reply_to_mismatch', 'Reply-To domain differs from From domain; may be legitimate '
                       '(helpdesks, mailing lists).', [f'From {email.sender}, Reply-To {email.reply_to}'])


# --- Links -----------------------------------------------------------------

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 't.ly', 's.id', 'v.gd',
}
_LOOKS_LIKE_URL = re.compile(r'^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$', re.IGNORECASE)


def _link_rule(email, predicate, describe=lambda link: link['url']):
    return [describe(link) for link in email.links if predicate(link)]


@rule
def display_url_mismatch(email):
    evidence = []
    for link in email.links:
        for shown in link['display_texts']:
            if not _LOOKS_LIKE_URL.match(shown):
                continue
            shown_host = hostname(shown if '://' in shown else 'http://' + shown)
            if registrable_domain(shown_host) != link['registrable_domain']:
                evidence.append(f'shows {shown} but links to {link["url"]}')
    if evidence:
        return Finding('display_url_mismatch', 'Visible link text names a different domain than the real destination.',
                       evidence)


@rule
def ip_address_link(email):
    evidence = _link_rule(email, lambda link: is_ip_host(link['hostname']))
    if evidence:
        return Finding('ip_address_link', 'Link points to a raw IP address instead of a domain name.', evidence)


@rule
def punycode_link(email):
    evidence = _link_rule(email, lambda link: 'xn--' in link['hostname'] or not link['hostname'].isascii())
    if evidence:
        return Finding('punycode_link', 'Link uses an internationalised (punycode) domain, a common lookalike '
                       'technique.', evidence)


def _has_userinfo(url):
    try:
        return urlsplit(url).username is not None
    except ValueError:
        return False


@rule
def credentials_in_url(email):
    evidence = _link_rule(email, lambda link: _has_userinfo(link['url']))
    if evidence:
        return Finding('credentials_in_url', 'Link contains "@" before the host, so the text before it is ignored '
                       '(e.g. https://bank.example@evil.example).', evidence)


@rule
def url_shortener(email):
    evidence = _link_rule(email, lambda link: link['hostname'] in URL_SHORTENERS)
    if evidence:
        return Finding('url_shortener', 'Link uses a URL shortener, which hides the real destination.', evidence)


@rule
def link_domain_mismatch(email):
    sender = registrable_domain(email.sender_domain)
    if not sender:
        return None
    others = sorted({link['registrable_domain'] for link in email.links
                     if link['registrable_domain'] and link['registrable_domain'] != sender})
    if others:
        return Finding('link_domain_mismatch', f'Links go to domains other than the sender\'s ({sender}); common '
                       'in legitimate newsletters too.', others)


# --- Attachments -------------------------------------------------------------

EXECUTABLE_EXTENSIONS = {'exe', 'scr', 'com', 'pif', 'msi', 'dll', 'cpl', 'bat', 'cmd'}
RISKY_EXTENSIONS = EXECUTABLE_EXTENSIONS | {
    'html', 'htm', 'shtml', 'xhtml', 'svg', 'hta', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'jar',
    'lnk', 'url', 'iso', 'img', 'vhd', 'vhdx', 'one', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'reg', 'chm',
}
ARCHIVE_EXTENSIONS = {'zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'ace', 'arj', 'xz', 'bz2'}
DOCUMENT_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg',
                       'png', 'gif'}
EXPECTED_TYPE = {
    'pdf': 'pdf', 'docx': 'zip_container', 'xlsx': 'zip_container', 'pptx': 'zip_container', 'zip': 'zip_container',
    'doc': 'ole_compound', 'xls': 'ole_compound', 'ppt': 'ole_compound', 'msg': 'ole_compound',
    'rar': 'rar', '7z': '7z',
}
_BIDI_CONTROLS = {'‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩'}


def _basename(filename):
    return re.split(r'[\\/]', filename)[-1]


def _extensions(filename):
    """Extensions in order, as Windows reads them (trailing dots/spaces dropped): a.pdf.exe -> ['pdf', 'exe']."""
    name = _basename(filename).rstrip(' .').lower()
    return [ext.strip() for ext in name.split('.')[1:]]


def _last_ext(attachment):
    exts = _extensions(attachment['filename'])
    return exts[-1] if exts else ''


@rule
def risky_attachment(email):
    evidence = [a['filename'] for a in email.attachments if _last_ext(a) in RISKY_EXTENSIONS]
    if evidence:
        return Finding('risky_attachment', 'Attachment type is commonly used to deliver malware or fake login pages '
                       '(HTML, script, shortcut, disk image, macro document or executable).', evidence)


@rule
def archive_attachment(email):
    evidence = [a['filename'] for a in email.attachments if _last_ext(a) in ARCHIVE_EXTENSIONS]
    if evidence:
        return Finding('archive_attachment', 'Compressed archive attached; contents cannot be inspected and may hide '
                       'executables.', evidence)


@rule
def double_extension(email):
    evidence = []
    for attachment in email.attachments:
        exts = _extensions(attachment['filename'])
        if len(exts) >= 2 and exts[-2] in DOCUMENT_EXTENSIONS and exts[-1] in RISKY_EXTENSIONS | ARCHIVE_EXTENSIONS:
            evidence.append(attachment['filename'])
    if evidence:
        return Finding('double_extension', 'Filename disguises its real type behind a document extension '
                       '(e.g. invoice.pdf.exe).', evidence)


@rule
def filename_obfuscation(email):
    evidence = [a['filename'] for a in email.attachments
                if set(a['filename']) & _BIDI_CONTROLS or re.search(r'\s{3,}\.\w+\s*$', a['filename'])]
    if evidence:
        return Finding('filename_obfuscation', 'Filename uses hidden text-direction characters or padding to hide its '
                       'real extension.', [ascii(name) for name in evidence])


@rule
def disguised_executable(email):
    evidence = [f'{a["filename"]} contains a {a["detected_type"]}' for a in email.attachments
                if a['detected_type'] in ('windows_executable', 'elf_executable')
                and _last_ext(a) not in EXECUTABLE_EXTENSIONS]
    if evidence:
        return Finding('disguised_executable', 'Attachment is a program but its name says otherwise.', evidence)


@rule
def attachment_type_mismatch(email):
    evidence = []
    for attachment in email.attachments:
        expected = EXPECTED_TYPE.get(_last_ext(attachment))
        detected = attachment['detected_type']
        if (expected and attachment['size_bytes'] and detected != expected
                and detected not in ('windows_executable', 'elf_executable')):
            evidence.append(f'{attachment["filename"]}: expected {expected}, found {detected or "unrecognised data"}')
    if evidence:
        return Finding('attachment_type_mismatch', 'Attachment contents do not match its file extension.', evidence)
