"""FastAPI entry-point — Email Threat Forensics backend.

Wires Stage 1 (ingestion & hop traceback), Stage 2 (protocol authentication & GeoIP),
and Stage 3 URL/obfuscation extraction into the unified MasterForensicReport contract.

Pipeline at ``POST /api/analyze``
---------------------------------
::

    UploadFile (bytes)
        │
        ▼
    ingest.extract_evidence(bytes, filename)          → EvidenceMetadata
    ingest.parse_payload(bytes, filename)             → EmailPayload
        │
        ├── hop_tracer.extract_origin_ip_from_payload(...) → str
        ├── auth_verifier.verify_from_payload(payload)     → ProtocolForensics
        └── domain_geo.resolve(from_addr, ip)              → OriginNetwork
        │
        ├── extractor.detect_zero_font_obfuscation(html)   → visible_text, hidden_cues
        └── extractor.extract_and_analyze_urls(html)       → List[SuspiciousURL]
        │
        ▼
    MasterForensicReport (response_model)
"""

from __future__ import annotations

import logging
import uuid
from typing import List

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.network import auth_verifier, domain_geo, hop_tracer, ingest
from app.intent.extractor import detect_zero_font_obfuscation, extract_and_analyze_urls
from app.schemas.forensic_report import (
    AttachmentReport,
    ChainOfCustodyEntry,
    EvidenceMetadata,
    GraphTopology,
    MasterForensicReport,
    OriginNetwork,
    ProtocolForensics,
    SuspiciousURL,
    ThreatIntent,
)

logger = logging.getLogger(__name__)

# FastAPI app & CORS configuration
app = FastAPI(
    title="Email Threat Forensics API",
    description=(
        "DFIR pipeline for SIH Problem Statement 106 — exposes the unified "
        "MasterForensicReport contract across network, domain, and intent layers."
    ),
    version="0.3.0",
)

# Permissive CORS for local Next.js frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Lightweight liveness probe."""
    return {
        "status": "ok",
        "pipeline_stages_active": [
            "ingest",
            "hop_tracer",
            "auth_verifier",
            "domain_geo",
            "url_and_obfuscation_extractor",
        ],
        "pipeline_stages_pending": [
            "stage3_nlp_semantic_engine",
            "stage4_attribution_and_vt",
            "stage5_custody_anchoring",
        ],
    }


@app.post(
    "/api/analyze",
    response_model=MasterForensicReport,
    tags=["analysis"],
    summary="Run forensic extraction across Stages 1, 2, and 3 on a single email submission.",
)
async def analyze(file: UploadFile = File(...)) -> MasterForensicReport:
    """Accept an .eml or .msg upload and return a unified MasterForensicReport."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Missing file upload")

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Empty file payload")

    try:
        report = _analyse_bytes(payload, file.filename)
    except Exception as exc:  # noqa: BLE001 — prevent raw 500 leaks
        logger.exception("analysis failed for %s", file.filename)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

    return report


def _analyse_bytes(payload: bytes, filename: str) -> MasterForensicReport:
    """Execute ingestion, origin network resolution, and body analysis against raw bytes."""
    # STAGE 1: Evidence hashing & RFC 5322 parsing
    evidence: EvidenceMetadata = ingest.extract_evidence(payload, filename)
    parsed = ingest.parse_payload(payload, filename)

    # STAGE 1 & 2: Hop tracing, authentication, and origin enrichment
    origin_ip = hop_tracer.extract_origin_ip_from_payload(parsed)
    protocol: ProtocolForensics = auth_verifier.verify_from_payload(parsed)
    origin: OriginNetwork = domain_geo.resolve(
        from_address=parsed.from_address or "",
        ip=origin_ip,
    )

    # STAGE 3: Hidden-text de-obfuscation & URL mismatch extraction
    html_source = parsed.html_body or ""
    _, hidden_chunks = detect_zero_font_obfuscation(html_source)
    raw_urls = extract_and_analyze_urls(html_source)

    suspicious_urls: List[SuspiciousURL] = [
        SuspiciousURL(
            anchor_text=u.get("anchor_text", "<empty>"),
            destination=u.get("destination", ""),
            is_mismatch=bool(u.get("is_mismatch", False)),
            domain=u.get("dest_domain", "unknown"),
        )
        for u in raw_urls
    ]

    # Rule-based threat scoring from extraction indicators
    mismatch_count = sum(1 for u in raw_urls if u.get("is_mismatch"))
    redirector_count = sum(1 for u in raw_urls if u.get("is_redirector"))
    userinfo_count = sum(1 for u in raw_urls if u.get("has_userinfo"))

    calculated_risk = min(
        100,
        (mismatch_count * 35)
        + (redirector_count * 20)
        + (userinfo_count * 25)
        + (len(hidden_chunks) * 20),
    )

    intent = ThreatIntent(
        primary_intent="SUSPICIOUS" if calculated_risk >= 35 else "BENIGN",
        risk_score=calculated_risk,
        urgency_score=0.0,
        flagged_coercion_cues=hidden_chunks,
        suspicious_urls=suspicious_urls,
    )

    # STAGES 4 & 5: Placeholders for attachment triage and graph topology
    attachment_forensics: List[AttachmentReport] = _placeholder_attachments(parsed)
    topology = GraphTopology(nodes=[], edges=[], campaign_cluster_id=None)
    chain_of_custody: List[ChainOfCustodyEntry] = _placeholder_chain(evidence)

    return MasterForensicReport(
        case_id=str(uuid.uuid4()),
        evidence=evidence,
        protocol_forensics=protocol,
        origin_network=origin,
        threat_intent=intent,
        attachment_forensics=attachment_forensics,
        graph_topology=topology,
        chain_of_custody=chain_of_custody,
    )


def _placeholder_attachments(parsed: ingest.EmailPayload) -> List[AttachmentReport]:
    """Populate initial attachment list until Stage 4 hash verification ships."""
    return [
        AttachmentReport(
            filename=att.filename,
            detected_magic=att.content_type,
            risk="PENDING_TRIAGE",
        )
        for att in parsed.attachments
    ]


def _placeholder_chain(evidence: EvidenceMetadata) -> List[ChainOfCustodyEntry]:
    """Genesis entry for chain of custody."""
    return [
        ChainOfCustodyEntry(
            sequence=0,
            timestamp=evidence.ingestion_timestamp,
            action="INTAKE",
            actor="system/ingest",
            prev_hash="0" * 64,
            entry_hash=evidence.sha256,
        )
    ]


__all__ = ["app", "analyze"]
