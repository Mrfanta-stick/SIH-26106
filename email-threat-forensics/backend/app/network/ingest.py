"""
-payload ingestion.

Task:
* Accept either raw RFC 5322 (.eml) bytes or Microsoft MAPI (.msg) bytes.
* Compute the SHA-256 fingerprint of the original payload (never of a
  re-serialised message — chain-of-custody MUST be bit-identical).
* Normalise the parsed result into a single intermediate representation that
  Stage 1 & 2 helpers (and, later, Stage 3-5 stages) can consume:

    * headers :- collapsed, case-preserving dict of original headers.
    * text_body :- best-effort plaintext body.
    * html_body :- best-effort HTML body (may be empty).
    * attachments :- list of ParsedAttachment (filename, bytes, mime) - Class object.
    * from_address :- RFC 5322 "From:" address (lowercased).
    * return_path :- envelope "Return-Path:" (lowercased).
    * reply_to :- optional "Reply-To:" (lowercased).
    * received_chain :- raw "Received:" headers in original order.

Design: 
* We rely on Python's stdlib email for RFC 5322, it correctly unfolds
  folded headers, decodes "=?charset?Q?...?=" encoded-words, and is resilient
  to malformed MIME boundaries.
* For MAPI we use extract_msg, which exposes the original transport
  headers via the transportMessageHeaders named property; we re-parse
  those through email so downstream code never has to branch on format.
* Exceptions are swallowed into sane defaults ("", []) rather than
  raised.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.forensic_report import EvidenceMetadata

logger = logging.getLogger(__name__)


# Intermediate representation — not part of the master contract, but kept as a
# Pydantic model so it composes cleanly with the rest of the pipeline.
class ParsedAttachment(BaseModel):
    #One attachment lifted verbatim from the payload.

    model_config = ConfigDict(extra="forbid")

    filename: str
    content_type: str
    data: bytes


class EmailPayload(BaseModel):
    #Format-agnostic intermediate produced by parse_payload().

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    # Headers are kept as a dict[str, str]; lists collapse into single strings.
    headers: Dict[str, str] = Field(default_factory=dict)
    text_body: str = ""
    html_body: str = ""
    attachments: List[ParsedAttachment] = Field(default_factory=list)
    from_address: str = ""
    return_path: str = ""
    reply_to: Optional[str] = None
    received_chain: List[str] = Field(default_factory=list)


# Public entry points
def extract_evidence(payload: bytes, filename: str) -> EvidenceMetadata:
    """
    Compute the chain-of-custody metadata for an arbitrary submission.

    This is the designated contract slice for ./app/network/ingest.py.
    It is intentionally format-agnostic, SHA-256 hashes the raw bytes
    regardless of whether they are .eml or .msg.
    """
    sha256 = hashlib.sha256(payload).hexdigest()
    timestamp = (
        datetime.now(tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    return EvidenceMetadata(
        filename=filename or "untitled",
        sha256=sha256,
        ingestion_timestamp=timestamp,
    )


def parse_payload(payload: bytes, filename: str) -> EmailPayload:
    """
    Parse the submission into a uniform intermediate representation.
    The dispatch is purely extension-based; unknown extensions fall back to
    RFC 5322.
    """
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".msg":
        return _parse_msg(payload, filename)
    return _parse_eml(payload, filename)


# RFC 5322 — .eml parsing
class _SafeBytesParser(BytesParser):
    # BytesParser that swaps to a permissive policy and never raises.

    def parse(self, fp, headersonly=False):  # type: ignore[override]
        try:
            return super().parse(fp, headersonly=headersonly)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            logger.warning("email parse error, returning empty message: %s", exc)
            return Message()


def _parse_eml(payload: bytes, filename: str) -> EmailPayload:
    msg = _SafeBytesParser(policy=policy.default).parsebytes(payload or b"")

    headers = _collapse_headers(msg)
    text_body, html_body = _split_bodies(msg)
    attachments = _walk_attachments(msg)

    from_addr = _extract_address(headers.get("From", ""))
    return_path = _extract_address(headers.get("Return-Path", ""))
    reply_to = _extract_address(headers.get("Reply-To", "")) or None

    # Important: capture each Received: header as a separate entry so
    # downstream code can iterate over hops in wire order, instead of
    # receiving a single newline-joined blob.
    received_chain: List[str] = list(msg.get_all("Received") or [])

    return EmailPayload(
        headers=headers,
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
        from_address=from_addr,
        return_path=return_path,
        reply_to=reply_to,
        received_chain=received_chain,
    )


def _collapse_headers(msg: Message) -> Dict[str, str]:
    # Produce a single-string-per-header dictionary preserving original casing.
    out: Dict[str, str] = {}
    for key in msg.keys():
        # msg.get_all(key) already unfolds continuation lines.
        values = msg.get_all(key, failobj=[])
        if not values:
            out[key] = ""
            continue
        out[key] = "\n".join(values)
    return out


def _split_bodies(msg: Message) -> Tuple[str, str]:
    # Return (text_body, html_body) from a (possibly multipart) message.
    text_parts: List[str] = []
    html_parts: List[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        ctype = (part.get_content_type() or "").lower()
        disposition = (part.get_content_disposition() or "").lower()
        if "attachment" in disposition:
            continue

        try:
            raw = part.get_payload(decode=True) or b""
        except Exception:
            raw = b""

        if isinstance(raw, bytes):
            charset = part.get_content_charset() or "utf-8"
            payload = raw.decode(charset, errors="replace")
        elif isinstance(raw, str):
            payload = raw
        else:
            continue

        if not payload.strip():
            continue

        if ctype == "text/plain":
            text_parts.append(payload)
        elif ctype == "text/html":
            html_parts.append(payload)

    # Prefer HTML only if no text-body is available
    return "\n\n".join(text_parts), "\n\n".join(html_parts)


def _walk_attachments(msg: Message) -> List[ParsedAttachment]:
    out: List[ParsedAttachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" not in disposition and not part.get_filename():
            continue
        filename = (
            part.get_filename()
            or _guess_attachment_name(part)
            or "unnamed.bin"
        )
        try:
            raw_payload = part.get_payload(decode=True)
            if isinstance(raw_payload, bytes):
                blob = raw_payload
            elif isinstance(raw_payload, str):
                blob = raw_payload.encode("utf-8", errors="replace")
            else:
                blob = b""
        except Exception as exc:  # noqa: BLE001
            logger.warning("attachment decode failed for %s: %s", filename, exc)
            blob = b""
        out.append(
            ParsedAttachment(
                filename=filename,
                content_type=part.get_content_type() or "application/octet-stream",
                data=blob,
            )
        )
    return out


def _guess_attachment_name(part: Message) -> str:
    # Crude filename derivation from content-type when Content-Disposition lacks one.
    ctype = part.get_content_type() or ""
    if not ctype:
        return ""
    ext = ctype.split("/")[-1].split("+")[0] or "bin"
    return f"part.{ext}"


def _extract_address(value: str) -> str:
    # Best-effort extraction of the first full email address from a header value.
    if not value:
        return ""
    # getaddresses returns (display_name, addr_spec) tuples.
    for _, addr in getaddresses([value]):
        if addr and "@" in addr:
            return addr.lower().strip()
    _, fallback = parseaddr(value)
    return (fallback or "").lower().strip()


# MAPI (.msg) parsing via extract_msg
def _parse_msg(payload: bytes, filename: str) -> EmailPayload:
    try:
        import extract_msg  # type: ignore  # local import — optional dependency.
    except ImportError:
        logger.error(
            "extract_msg not installed — cannot parse .msg payload for %s; "
            "falling back to empty representation", filename,
        )
        return EmailPayload(headers={"X-Ingest-Error": "extract_msg-missing"})

    try:
        msg = extract_msg.Message(payload)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        logger.warning("extract_msg failed on %s: %s", filename, exc)
        return EmailPayload(headers={"X-Ingest-Error": str(exc)})

    # 1. Re-parse the transport headers as if they were RFC 5322.
    transport = getattr(msg, "transportMessageHeaders", None) or ""
    headers: Dict[str, str] = {}
    received_chain: List[str] = []
    if transport:
        header_msg = _SafeBytesParser(policy=policy.default).parsebytes(
            transport.encode("utf-8", errors="replace")
        )
        headers = _collapse_headers(header_msg)
        for k, v in headers.items():
            if k.lower() == "received":
                received_chain.append(v)

    # 2. Bodies.
    try:
        text_body = (msg.body or "") if hasattr(msg, "body") else ""
    except Exception:  # noqa: BLE001
        text_body = ""
    try:
        html_body = (msg.htmlBody or b"").decode("utf-8", errors="replace") \
            if getattr(msg, "htmlBody", None) else ""
    except Exception:  # noqa: BLE001
        html_body = ""

    # extract_msg exposes an RTF body as rtfBody — we strip the markup
    # crudely to keep the plaintext table populated for downstream NLP.
    if not text_body:
        try:
            rtf = getattr(msg, "rtfBody", "") or ""
            text_body = _strip_rtf(rtf) if rtf else ""
        except Exception:  # noqa: BLE001
            text_body = ""

    # 3. Attachments.
    attachments: List[ParsedAttachment] = []
    for att in _safe_iter_attachments(msg):
        try:
            data = att.data or b""
        except Exception:  # noqa: BLE001
            data = b""
        attachments.append(
            ParsedAttachment(
                filename=getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or "unnamed.bin",
                content_type=getattr(att, "mimeType", None) or "application/octet-stream",
                data=data,
            )
        )

    # 4. Envelope addresses — fall back to properties exposed by extract_msg.
    from_addr = (getattr(msg, "sender", None) or headers.get("From", "")).lower()
    return_path = (headers.get("Return-Path", "") or "").lower()
    reply_to = headers.get("Reply-To")

    return EmailPayload(
        headers=headers or {"X-Ingest-Source": "extract_msg"},
        text_body=text_body or "",
        html_body=html_body or "",
        attachments=attachments,
        from_address=_extract_address(from_addr),
        return_path=_extract_address(return_path),
        reply_to=(_extract_address(reply_to) if reply_to else None),
        received_chain=received_chain,
    )


def _safe_iter_attachments(msg: Any) -> List[Any]:
    try:
        return list(msg.attachments)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return []


_RTF_TAG = re.compile(r"\\([a-z]+)(-?\d+)? ?")
_RTF_BRACE = re.compile(r"[{}]")


def _strip_rtf(rtf: str) -> str:
    # Raw RTF -> text used as a last-ditch fallback for MAPI bodies.
    if not rtf:
        return ""
    try:
        import striprtf  # type: ignore  # optional — only present in dev envs.
        return striprtf.rtf_to_text(rtf)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    # Crude fallback: drop control words and braces.
    cleaned = _RTF_TAG.sub(" ", rtf)
    cleaned = _RTF_BRACE.sub("", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


__all__ = [
    "EmailPayload",
    "EvidenceMetadata",
    "ParsedAttachment",
    "extract_evidence",
    "parse_payload",
]
