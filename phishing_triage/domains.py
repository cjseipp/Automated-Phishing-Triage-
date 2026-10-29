"""Hostname and domain helpers. Pure string handling; no DNS or network access."""
from __future__ import annotations
import ipaddress
from urllib.parse import urlsplit

# Common two-label public suffixes. Without a full Public Suffix List, other
# multi-label suffixes fall back to "last two labels".
_MULTI_PART_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'co.jp', 'or.jp', 'ne.jp', 'co.za', 'org.za',
    'com.br', 'com.mx', 'com.ar', 'com.cn', 'com.tw', 'com.sg', 'co.in', 'co.kr',
}


def hostname(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or '').rstrip('.').lower()
    except ValueError:
        return ''


def is_ip_host(host: str) -> bool:
    """True for dotted/IPv6 addresses and obfuscated forms such as 3232235777 or 0x7f000001."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return host.isdigit() or (host.startswith('0x') and all(c in '0123456789abcdef' for c in host[2:]) and len(host) > 2)


def registrable_domain(host: str) -> str:
    """Approximate the organisation-level domain: www.mail.paypal.com -> paypal.com."""
    host = host.rstrip('.').lower()
    if not host or is_ip_host(host):
        return host
    labels = host.split('.')
    if len(labels) >= 3 and '.'.join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def email_domain(address: str) -> str:
    return address.rsplit('@', 1)[-1].rstrip('.').lower() if '@' in address else ''
