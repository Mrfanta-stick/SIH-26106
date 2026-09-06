"""
chronological Received: chain reconstruction.

The earliest public IP encountered in the chain is the one that should feed
OriginNetwork because:

1. The first entry (top of the message) is the destination / receiving MTA;
2. The last entry (bottom of the message) is the originating submission hop;
3. Intermediate hops can sit inside private RFC 1918 networks and must be
  skipped using %ipaddress rather than a fragile regex.

This module has no designated master-contract return of its own, the
master contract does not model multi-hop paths. Its primary public entry
(extract_origin_ip()) is consumed by app.network.domain_geo.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from email import policy
from email.parser import BytesParser
from email.message import Message

from app.network.ingest import EmailPayload

logger = logging.getLogger(__name__)


# Public dataclass — a richer hop description, used for debug / visualisation.
@dataclass(frozen=True)
class ReceivedHop:
    # One observed Received: hop with the IP that best identifies it.

    raw: str
    hostname: Optional[str]
    ip: Optional[str] # Sender IP
    by_host: Optional[str] # Receiving Host Name
    by_ip: Optional[str] = None # Receiving Host IP
    timestamp_hint: Optional[str] = None

    def is_public(self) -> bool:
        if not self.ip:
            return False
        return _is_public(self.ip)

    def is_by_public(self) -> bool:
        if not self.by_ip:
            return False
        return _is_public(self.by_ip)
    

# Regular expressions used to extract Received: headers.

# Standalone IPv4 / IPv6 patterns — robust to bracket nesting such as the
# very common (mx.example.org [203.0.113.45]) shape used in Received
# headers, where the closing paren sits *outside* the IP bracket.
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])"
)
_RE_FROM_HOST = re.compile(r"from\s+(?P<host>[A-Za-z0-9_.\-:\[\]]+)")
_RE_BY_HOST = re.compile(r"by\s+(?P<host>[A-Za-z0-9_.\-:]+)")
_RE_BY_IP = re.compile(
    r"by\s+[A-Za-z0-9_.\-:]+\s*(?:\([^)]*\)\s*)?\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\]?",
    re.IGNORECASE,
)
_RE_DATE_HINT = re.compile(
    r";\s*(?P<date>[A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+"
    r"\d{2}:\d{2}(?::\d{2})?(?:\s*[+\-]\d{4})?\s*(?:\([^)]+\))?)"
)

# Fallbacks exercised when the chain yields nothing useful.
_RE_X_ORIGINATING = re.compile(
    r"X-Originating-IP\s*:\s*\[?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]?",
    re.IGNORECASE,
)


# Public API
def trace(payload: bytes) -> List[ReceivedHop]:
    """Parse the ``Received:`` chain in *chronological order*.

    Returns a list ordered such that ``hops[0]`` is the first (originating)
    hop and ``hops[-1]`` is the last (delivering) hop. This is the reverse of
    the on-the-wire order, in which the most recent hop appears first.
    """
    msg = _safe_parse(payload)
    received = msg.get_all("Received") or []
    hops = [_parse_one(h) for h in received]
    hops.reverse()  # chronological order
    return hops


def extract_origin_ip(payload: bytes) -> str:
    """Return the earliest **public** IP found in the chain (string).

    Falls back through three layers, in order::

        1. Public IP from the chronologically-earliest ``Received:`` hop.
        2. ``X-Originating-IP`` / ``X-Sender-IP`` header.
        3. Empty string — caller should treat this as "unknown origin".

    The function is deliberately side-effect free and defensive: the goal is
    *never* to raise on a malformed header.
    """
    for hop in trace(payload):
        if hop.is_public() and hop.ip:
            return hop.ip  # type: ignore[return-value]

    # Last-ditch fallbacks.
    for header_name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        match = _RE_X_ORIGINATING.search(
            _safe_header(payload, header_name) or ""
        )
        if match:
            candidate = match.group("ip")
            if _is_public(candidate):
                return candidate

    return ""


def extract_origin_ip_from_payload(payload_model: EmailPayload) -> str:
    """Same contract as :func:`extract_origin_ip`, but consumes a pre-parsed
    :class:`EmailPayload`. Avoids a second RFC-5322 pass inside the pipeline.
    """
    received_chain: List[str] = list(reversed(payload_model.received_chain))
    for raw in received_chain:
        hop = _parse_one(raw)
        if hop.is_public() and hop.ip:
            return hop.ip  # type: ignore[return-value]

    # Look for the well-known client-IP headers we already parsed.
    for header_name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        match = _RE_X_ORIGINATING.search(payload_model.headers.get(header_name, ""))
        if match and _is_public(match.group("ip")):
            return match.group("ip")
    return ""


# Internal helpers
def _safe_parse(payload: bytes) -> Message:
    """Parse ``payload`` with a permissive email policy; never raises."""
    try:
        return BytesParser(policy=policy.default).parsebytes(payload or b"")
    except Exception as exc:  # noqa: BLE001
        logger.warning("hop_tracer: header parse failed: %s", exc)
        return Message()


def _safe_header(payload: bytes, name: str) -> Optional[str]:
    return _safe_parse(payload).get(name)


def _parse_one(raw: str) -> ReceivedHop:
    """Parse a single ``Received:`` block into a :class:`ReceivedHop`.

    The IP is whichever valid IPv4 / IPv6 literal appears first in the header
    — real-world messages usually only carry one, and the receiving-server IP
    embedded in the host pointer is the one analysts care about.
    """
    ip = _first_valid_ip(raw)

    by_ip_match = _RE_BY_IP.search(raw)
    by_ip = (
        by_ip_match.group("ip")
        if by_ip_match and _is_valid_ip( by_ip_match.group("ip"))
        else None
    )

    from_match = _RE_FROM_HOST.search(raw)
    by_match = _RE_BY_HOST.search(raw)
    date_match = _RE_DATE_HINT.search(raw)

    return ReceivedHop(
        raw=raw,
        hostname=from_match.group("host").strip("[] ") if from_match else None,
        ip=ip,
        by_host=by_match.group("host").strip(" []") if by_match else None,
        by_ip=by_ip,
        timestamp_hint=date_match.group("date").strip() if date_match else None,
    )


def _first_valid_ip(text: str) -> Optional[str]:
    """Return the first valid IPv4 or IPv6 literal found in ``text``."""
    for match in _RE_IPV4.finditer(text):
        candidate = match.group(0)
        if _is_valid_ip(candidate):
            return candidate
    for match in _RE_IPV6.finditer(text):
        candidate = match.group(0)
        if _is_valid_ip(candidate):
            return candidate
    return None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _is_public(value: str) -> bool:
    if not _is_valid_ip(value):
        return False
    addr = ipaddress.ip_address(value)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


__all__ = [
    "ReceivedHop",
    "extract_origin_ip",
    "extract_origin_ip_from_payload",
    "trace",
]
