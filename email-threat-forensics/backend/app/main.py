"""
FastAPI entry-point — Email Threat Forensics backend.

Wires Stage 1 (ingestion & hop traceback), Stage 2 (protocol authentication & GeoIP),
Stage 3 (URL/obfuscation extraction), Stage 4 (attribution & attachment triage),
and St  age 5 (cryptographic custody ledger & court-ready PDF dossier).
"""

from __future__ import annotations

import os
import logging
import uuid
from typing import Dict, List

from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.network import auth_verifier, domain_geo, hop_tracer, ingest
from app.intent.extractor import detect_zero_font_obfuscation, extract_and_analyze_urls
from app.intent.intent import threat_intent
from app.attribution.master_builder import integrate
from app.custody.audit_ledger import append_custody_entry, verify_ledger_integrity
from app.custody.pdf_generator import generate_forensic_pdf
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

# In-MEMORY case cache to serve GET /api/case/{case_id}/export-pdf
REPORT_CACHE: Dict[str, MasterForensicReport] = {}

# FastAPI app & CORS configuration
app = FastAPI(
    title="Email Threat Forensics API",
    description=(
        "DFIR pipeline for SIH Problem Statement 106 — exposes the unified "
        "MasterForensicReport contract across network, domain, and intent layers."
    ),
    version="0.5.0",
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
    return {
        "status": "ok",
        "pipeline_stages_active": [
            "ingest",
            "hop_tracer",
            "auth_verifier",
            "domain_geo",
            "url_and_obfuscation_extractor",
            "stage3_nlp_semantic_engine",
            "attribution_and_attachment_triage",
            "custody_anchoring",
            "pdf_export",
        ],
        "pipeline_stages_pending": [],
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

    REPORT_CACHE[report.case_id] = report
    return report

@app.get(
    "/api/case/{case_id}/export-pdf",
    tags=["export"],
    summary="Export court-ready PDF dossier for a previously analysed case.",
)

async def export_pdf_by_id(case_id: str):
    # Retrieve case from memory and generate a court-admissible Weasyprint PDF.
    report = REPORT_CACHE.get(case_id)
    if not report:
        raise HTTPException(
            status_code = 404,
            detail=f"Case {case_id} not found."
        )

    try:
        pdf_bytes = generate_forensic_pdf(report)
    except Exception as e:
        logger.exception("PDF rendering failed for case %s", case_id)
        raise HTTPException(
            status_code = 500,
            detail=f"PDF generation failed. {e}",
        )

    return Response(
        content = pdf_bytes,
        media_type = "application/pdf",
        headers = {
            "Content-Disposition": f'attachment; filename="dossier_{case_id[:8]}.pdf"'
        },
    )

@app.post(
    "/api/export-pdf",
    tags=["export"],
    summary="Stateless PDF export directly accepting a MasterForensicReport JSON",
)

async def export_pdf_direct(report: MasterForensicReport):
    try:
        pdf_bytes = generate_forensic_pdf(report)
    except Exception as e:
        logger.exception("Direct PDF rendering failed")
        raise HTTPException(
            status_code = 500,
            detail = f"PDF generation failed. {e}"
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers= {
            "Content-Disposition": f'attachment; filename="dossier_{report.case_id[:8]}.pdf"'
        }
    )

def _analyse_bytes(payload: bytes, filename: str) -> MasterForensicReport:
    """Execute stages 1 through 5 against raw email bytes."""
    ledger: List[ChainOfCustodyEntry] = []

    # STAGE 1: Evidence hashing & RFC 5322 parsing
    evidence: EvidenceMetadata = ingest.extract_evidence(payload, filename)
    append_custody_entry(
        ledger,
        action=f"EVIDENCE_INTAKE (SHA-256: {evidence.sha256[:16]}…)",
        actor="system/ingest",
    )
    parsed = ingest.parse_payload(payload, filename)

    # STAGE 1 & 2: Hop tracing, authentication, and origin enrichment
    origin_ip = hop_tracer.extract_origin_ip_from_payload(parsed)
    protocol: ProtocolForensics = auth_verifier.verify_from_payload(parsed)
    origin: OriginNetwork = domain_geo.resolve(
        from_address=parsed.from_address or "",
        ip=origin_ip,
    )
    append_custody_entry(
        ledger,
        action=f"NETWORK_ENRICHMENT (Origin: {origin_ip or 'unknown'}, Country: {origin.country})",
        actor="system/network",
    )

    # STAGE 3: Zero-font extraction, semantic intent, and URL triage
    html_source = parsed.html_body or ""
    _, hidden_chunks = detect_zero_font_obfuscation(html_source)
    email_text = getattr(parsed, "text_body", None) or getattr(parsed, "body", "") or ""

    intent_result = threat_intent(
        email_text=email_text,
        html_content=html_source,
    )
    intent_data = intent_result.get("threat_intent", intent_result)

    # Merge NLP coercion cues with zero-font evasion chunks
    coercion_cues = list(
        dict.fromkeys(intent_data.get("flagged_coercion_cues", []) + hidden_chunks)
    )

    suspicious_urls: List[SuspiciousURL] = [
        SuspiciousURL(
            anchor_text=u.get("anchor_text", "<empty>"),
            destination=u.get("destination", ""),
            is_mismatch=bool(u.get("is_mismatch", False)),
            domain=u.get("domain") or u.get("dest_domain", "unknown"),
        )
        for u in intent_data.get("suspicious_urls", [])
    ]

    intent = ThreatIntent(
        primary_intent=intent_data.get("primary_intent", "UNKNOWN"),
        risk_score=int(round(intent_data.get("risk_score", 0))),
        urgency_score=float(intent_data.get("urgency_score", 0.0)),
        flagged_coercion_cues=coercion_cues,
        suspicious_urls=suspicious_urls,
    )

    append_custody_entry(
        ledger,
        action=f"INTENT_ANALYSIS (Risk: {intent.risk_score}, Intent: {intent.primary_intent})",
        actor="system/intent",
    )

    # STAGE 4: Static attachment triage and routing graph attribution
    attribution = integrate(
        payload,
        parsed,
        os.getenv("VT_API_KEY"),
    )
    stage4 = attribution["stage4_analysis"]
    attachment_forensics: List[AttachmentReport] = [
        AttachmentReport(
            filename=att["filename"],
            detected_magic=att["magic_type"],
            risk=att["risk"],
            size_bytes=att.get("size_bytes"),
            sha256=att.get("sha256"),
            virustotal_scan=att.get("virustotal_scan"),
        )
        for att in stage4["attachments"]
    ]
    topology = GraphTopology(**stage4["routing_graph"])
    append_custody_entry(
        ledger,
        action=f"ATTACHMENT_AND_GRAPH_TRIAGE (Attachments: {len(attachment_forensics)}, Nodes: {len(topology.nodes)})",
        actor="system/attribution",
    )

    # STAGE 5: Cryptographic Ledger Integrity Check
    if not verify_ledger_integrity(ledger):
        logger.error("Audit ledger integrity check failed during analysis pipeline")
        raise RuntimeError("Chain of custody ledger validation failed: hash chain broken.")

    return MasterForensicReport(
        case_id=str(uuid.uuid4()),
        evidence=evidence,
        protocol_forensics=protocol,
        origin_network=origin,
        threat_intent=intent,
        attachment_forensics=attachment_forensics,
        graph_topology=topology,
        chain_of_custody=ledger,
    )

__all__ = ["app", "analyze"]
