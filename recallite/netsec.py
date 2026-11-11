"""
recallite.netsec — SSRF protection for everything recallite fetches.

A /task URL is user data pointed at the network, so by default recallite
refuses to fetch anything that resolves to a non-public address:

    loopback        127.0.0.0/8, ::1          (your own services, vLLM, Ollama)
    private         10/8, 172.16/12, 192.168/16, fc00::/7
    link-local      169.254.0.0/16, fe80::/10 (cloud metadata lives here)
    reserved / unspecified / multicast

Every redirect hop is re-validated, so a public URL cannot bounce a fetch
into the internal network. Opt out deliberately per TaskManager
(allow_private=True), per call, or via RECALLITE_ALLOW_PRIVATE_URLS=1 —
for people who intentionally fetch from their own machines.

Known residual risk (documented, not hidden): hostname validation resolves
DNS, then urllib resolves again to connect — a hostile DNS server that
answers differently per query (DNS rebinding) could pass validation and
connect elsewhere. Single-resolution pinning requires bypassing TLS SNI
machinery; out of scope for a stdlib-only library. Mitigation: all resolved
addresses must be public, which defeats static split-horizon records.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

MAX_REDIRECTS = 3


class SSRFError(ValueError):
    """URL refused because it points at a non-public address."""


def _env_allows_private() -> bool:
    return (os.environ.get("RECALLITE_ALLOW_PRIVATE_URLS", "") == "1"
            or os.environ.get("MEMLAYER_ALLOW_PRIVATE_URLS", "") == "1")
    # the MEMLAYER_ spelling is honored for pre-rename deployments


def _addr_is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def validate_public_url(url: str, allow_private: bool = False) -> None:
    """Raise SSRFError unless every address the URL's host resolves to is
    public. Scheme must be http or https."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError("Only http:// and https:// URLs are allowed.")
    host = parsed.hostname
    if not host:
        raise SSRFError("URL has no host.")
    if allow_private or _env_allows_private():
        return
    # literal IP?
    try:
        ip = ipaddress.ip_address(host)
        if not _addr_is_public(ip):
            raise SSRFError(
                f"Refusing to fetch {host}: non-public address. "
                f"(allow_private=True or RECALLITE_ALLOW_PRIVATE_URLS=1 "
                f"to opt out.)")
        return
    except ValueError as e:
        if isinstance(e, SSRFError):
            raise
    # hostname: every resolved address must be public
    try:
        infos = socket.getaddrinfo(host, parsed.port or
                                   (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFError(f"Cannot resolve host {host}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _addr_is_public(ip):
            raise SSRFError(
                f"Refusing to fetch {host}: resolves to non-public address "
                f"{ip}. (allow_private=True or RECALLITE_ALLOW_PRIVATE_URLS=1 "
                f"to opt out.)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None     # we handle redirects ourselves, re-validating each


_opener = urllib.request.build_opener(_NoRedirect)


def safe_urlopen(url: str, timeout: int = 20, allow_private: bool = False,
                 user_agent: str = "recallite", _validator=validate_public_url):
    """urlopen with SSRF validation on the URL and on every redirect hop.
    Returns the final open response object."""
    seen = 0
    while True:
        _validator(url, allow_private=allow_private)
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        try:
            return _opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location")
                e.close()
                if not location:
                    raise
                seen += 1
                if seen > MAX_REDIRECTS:
                    raise SSRFError(
                        f"Too many redirects (> {MAX_REDIRECTS}).")
                url = urllib.parse.urljoin(url, location)
                continue
            raise
