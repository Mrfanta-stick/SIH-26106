"""
SPF / DKIM / DMARC verdict extraction + relaxed domain alignment.

Inputs:
1. payload: .eml / .msg.
2. from_address (optional): — RFC 5322 "From:" address. When omitted it is
  re-derived from the message body so the function can be called standalone.

Output:
app.schemas.forensic_report.ProtocolForensics

Verdict semantics: 
1. PASS :- the relevant method/token passed.
2. FAIL :- authentication explicitly failed.
3. SOFTFAIL :- only SPF returns this; treated as a soft failure for risk.
4. NONE :- no authentication record was found (default).

The Authentication-Results grammar we parse is RFC 7601 v2.2:

    Authentication-Results: <authserv-id>; <methodspec> ...

We split on the first ';' to separate the authserv-id from the method list,
then walk each top-level ";" separated token and lift verdict / reason.
"""

from __future__ import annotations

import logging
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from app.network.ingest import EmailPayload
from typing import List, Optional, Tuple

import tldextract

from app.schemas.forensic_report import (
    DomainAlignment,
    ProtocolForensics,
)

logger = logging.getLogger(__name__)


# Regular expressions
# A method-spec token looks like ``method=value reason=...``.
_RE_METHOD_HEADER = re.compile(
    r"(?P<method>spf|dkim|dmarc)\s*=\s*"
    r"(?P<result>pass|fail|softfail|none|temperror|permerror|neutral|policy|"
    r"hardfail|unknown)\b",
    re.IGNORECASE,
)

# Loose bracketed IPv4 / IPv6 capture — used as a fallback for extraction.
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# Allow the caller to pass either bytes or a pre-parsed message.
__all__ = ["ProtocolForensics", "verify", "verify_from_payload"]


# Public entry points
def verify(payload: bytes, from_address: Optional[str] = None) -> ProtocolForensics:
    """Convenience entry-point: parse ``payload`` and immediately verify it."""
    msg = _safe_parse(payload)
    if from_address is None:
        from_address = _first_address(msg.get("From", ""))
    return _verify_message(msg, from_address)


def verify_from_payload(
    parsed: EmailPayload,  # noqa: F821 - forward ref
) -> ProtocolForensics:
    # Verify using the already-parsed EmailPayload from ingest.
    from app.network.ingest import EmailPayload  # local import to break cycle
    if not isinstance(parsed, EmailPayload):  # pragma: no cover - type guard
        raise TypeError("verify_from_payload requires an EmailPayload instance")
    msg = _parsed_to_message(parsed)
    return _verify_message(msg, parsed.from_address)


# Core pipeline
def _verify_message(msg: Message, from_address: str) -> ProtocolForensics:
    # Parse SPF / DKIM / DMARC verdicts and compute relaxed alignment.
    spf_result, dkim_result, dmarc_result = _parse_authentication_results(msg)

    from_domain = _domain_of(from_address)
    return_path_domain = _domain_of(_first_address(msg.get("Return-Path", "")))
    reply_to_address = _first_address(msg.get("Reply-To", ""))
    reply_to_domain = _domain_of(reply_to_address) if reply_to_address else None

    # RFC 7489 §3.1 — DMARC alignment default is "relaxed", which we adopt.
    is_aligned = _is_relaxed_aligned(from_domain, return_path_domain)

    alignment = DomainAlignment(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        is_aligned=is_aligned,
    )

    return ProtocolForensics(
        spf=_canonicalise_verdict(spf_result),
        dkim=_canonicalise_verdict(dkim_result),
        dmarc=_canonicalise_verdict(dmarc_result),
        domain_alignment=alignment,
    )


# Authentication-Results parsing
def _parse_authentication_results(
    msg: Message,
) -> Tuple[str, str, str]:
    """
    Lift SPF / DKIM / DMARC verdicts out of the Authentication-Results header.

    We honour the first authoritative instance per RFC 7601 §3.1 — additional
    Authentication-Results blocks separated by indentation are merged into the
    same namespace, but only the first occurrence of each method wins.
    """
    raw = msg.get("Authentication-Results", "") or ""
    if not raw.strip():
        return "NONE", "NONE", "NONE"

    # One Authentication-Results header can carry multiple method tokens.
    spf = dkim = dmarc = ""

    # Walk every method token in the entire header (RFC 7601 allows multi-line
    # headers, but stdlib email already unfolds them for us).
    for match in _RE_METHOD_HEADER.finditer(raw):
        method = match.group("method").lower()
        result = match.group("result").lower()
        if method == "spf" and not spf:
            spf = result
        elif method == "dkim" and not dkim:
            dkim = result
        elif method == "dmarc" and not dmarc:
            dmarc = result

    # Some providers spell SPF/DKIM/DMARC verdict only in the policy.
    # sub-tokens (e.g. dmarc=fail (p=reject sp=reject)). The regex already
    # captures those because policy is in the alternation list, so the
    # canonical mapping below turns it into FAIL.
    return spf, dkim, dmarc


_VERDICT_CANONICAL = {
    "pass": "PASS",
    "fail": "FAIL",
    "hardfail": "FAIL",
    "softfail": "SOFTFAIL",
    "none": "NONE",
    "neutral": "NONE",
    "policy": "FAIL",
    "temperror": "NONE",
    "permerror": "NONE",
    "unknown": "NONE",
}


def _canonicalise_verdict(verdict: str) -> str:
    return _VERDICT_CANONICAL.get((verdict or "").lower(), "NONE")


# Domain & alignment helpers
def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def _registered(domain: str) -> str:
    # Return the eTLD+1 via tldextract, or the raw lowercased input.
    if not domain:
        return ""
    extracted = tldextract.extract(domain)
    if extracted.registered_domain:
        return extracted.registered_domain.lower()
    return domain.lower()


def _is_relaxed_aligned(from_domain: str, return_path_domain: str) -> bool:
    f = _registered(from_domain)
    r = _registered(return_path_domain)
    if not f or not r:
        return False
    return f == r


def _first_address(value: str) -> str:
    # Extract the first pure email address from a header value.
    if not value:
        return ""
    for _, addr in getaddresses([value]):
        if addr and "@" in addr:
            return addr.lower().strip()
    _, addr = parseaddr(value)
    return (addr or "").lower().strip()


# Message-parsing shims
def _safe_parse(payload: bytes) -> Message:
    try:
        return BytesParser(policy=policy.default).parsebytes(payload or b"")
    except Exception as exc:  # noqa: BLE001
        logger.warning("auth_verifier: header parse failed: %s", exc)
        return Message()


def _parsed_to_message(parsed: EmailPayload) -> Message:  # noqa: F821
    """
    Convert a EmailPayload object back into a stdlib Message for parsing.

    The conversion is non-destructive — we round-trip through RFC 5322 bytes
    so Python's authentication-parser grammar is exercised exactly as it would
    be on a raw .eml upload.
    """
    
    if not isinstance(parsed, EmailPayload):
        raise TypeError("expected EmailPayload")

    chunks: List[bytes] = []
    for key, value in parsed.headers.items():
        # Avoid the LF-in-value edge case by keeping each header one line.
        safe_value = value.replace("\r\n", " ").replace("\n", " ")
        chunks.append(f"{key}: {safe_value}\r\n".encode("utf-8", errors="replace"))
    chunks.append(b"\r\n")
    return _safe_parse(b"".join(chunks))
