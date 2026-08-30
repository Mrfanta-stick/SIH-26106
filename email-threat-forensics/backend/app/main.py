"""FastAPI entry-point — Email Threat Forensics backend.

This module wires **Stage 1 & 2 only** of the pipeline.  Stages 3 (``intent``),
4 (``attribution``) and 5 (``custody``) belong to Group 3 and are intentionally
left as well-typed *empty placeholders* so the API contract remains exercisable
end-to-end today and can be filled in incrementally tomorrow.

Pipeline at ``POST /api/analyze``
---------------------------------
::

    UploadFile (bytes)
        │
        ▼
    ingest.extract_evidence(bytes, filename)        → EvidenceMetadata
    ingest.parse_payload(bytes, filename)           → EmailPayload
        │
        ▼
    hop_tracer.extract_origin_ip_from_payload(...)  → str
    auth_verifier.verify_from_payload(payload)      → ProtocolForensics
    domain_geo.resolve(from_addr, ip)               → OriginNetwork
        │
        ▼
    stage 3 / 4 / 5 placeholder models              → ThreatIntent / etc.
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
from app.schemas.forensic_report import (
    AttachmentReport,
    ChainOfCustodyEntry,
    EvidenceMetadata,
    GraphEdge,
    GraphNode,
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
        "MasterForensicReport contract. Stage 1 & 2 only at this revision."
    ),
    version="0.2.0",
)

# Permissive CORS — the Group 1 Next.js frontend may run on any of these dev
# origins during local development.  The list can be tightened via an env var
# in production without code changes.
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


# API routes
@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Lightweight liveness probe — does not touch MaxMind or the filesystem."""
    return {
        "status": "ok",
        "pipeline_stages_active": ["ingest", "hop_tracer", "auth_verifier", "domain_geo"],
        "pipeline_stages_pending": [
            "stage3_intent", "stage4_attribution", "stage5_custody",
        ],
    }


@app.post(
    "/api/analyze",
    response_model=MasterForensicReport,
    tags=["analysis"],
    summary="Run Stage 1 & 2 of the DFIR pipeline on a single submission.",
)
async def analyze(file: UploadFile = File(...)) -> MasterForensicReport:
    """
    Accept an .eml or .msg upload and return a partial MasterForensicReport.

    The response is always a fully-typed MasterForensicReport object;
    Group 3 fields are returned as empty placeholders so the frontend can
    render the document layout until those stages land.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Missing file upload")

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Empty file payload")

    try:
        report = _analyse_bytes(payload, file.filename)
    except Exception as exc:  # noqa: BLE001 — never leak 5xx on bad input
        logger.exception("analysis failed for %s", file.filename)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

    return report


# Stage 1 & 2 wiring — kept in a free function for unit-testability.
def _analyse_bytes(payload: bytes, filename: str) -> MasterForensicReport:
    # Run Stage 1 & 2 against the raw bytes; assemble the master contract.
    # Stage 1
    evidence: EvidenceMetadata = ingest.extract_evidence(payload, filename)
    parsed = ingest.parse_payload(payload, filename)

    # Stage 1 helper → Stage 2 helper
    origin_ip = hop_tracer.extract_origin_ip_from_payload(parsed)

    # Stage 2
    protocol: ProtocolForensics = auth_verifier.verify_from_payload(parsed)
    origin: OriginNetwork = domain_geo.resolve(
        from_address=parsed.from_address or "",
        ip=origin_ip,
    )

    # Stage 3/4/5 — placeholders so the master contract is complete.
    intent = ThreatIntent(
        primary_intent="BENIGN",
        risk_score=0,
        urgency_score=0.0,
        flagged_coercion_cues=[],
        suspicious_urls=_placeholder_suspicious_urls(),
    )
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


# Placeholder generators — replaced wholesale by Group 3 once their modules
# land. Kept in one place so they can be deleted in a single PR.
def _placeholder_suspicious_urls() -> List[SuspiciousURL]:
    # Intent stage will populate this for real; an empty list keeps the
    # contract honest about "no finding yet".
    return []


def _placeholder_attachments(parsed: ingest.EmailPayload) -> List[AttachmentReport]:
    """
    Pretend we have a static-triage verdict for every observed attachment.

    Stage 4 (app.attribution.attachment) will replace this with real
    libmagic + zip-bomb analysis once it ships. Until then we expose the
    filename so the UI can show the file list without an empty panel.
    """
    out: List[AttachmentReport] = []
    for att in parsed.attachments:
        out.append(
            AttachmentReport(
                filename=att.filename,
                detected_magic=att.content_type,
                risk="PENDING_TRIAGE",
            )
        )
    return out


def _placeholder_chain(evidence: EvidenceMetadata) -> List[ChainOfCustodyEntry]:
    """
    Seed the chain of custody with a single 'INTAKE' entry.

    Stage 5 will append further entries; for now we record the SHA-256 and
    timestamp from :class:`EvidenceMetadata` as our genesis record.
    """
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
