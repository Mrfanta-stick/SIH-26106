"""
Pydantic V2 schemas for the Email Threat Forensics DFIR platform.

The unified master contract lives in ./app/schemas/forensic_report. Every
backend pipeline stage MUST read from or write to the models defined there.
"""

from app.schemas.forensic_report import (
    AttachmentReport,
    ChainOfCustodyEntry,
    DomainAlignment,
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

__all__ = [
    "AttachmentReport",
    "ChainOfCustodyEntry",
    "DomainAlignment",
    "EvidenceMetadata",
    "GraphEdge",
    "GraphNode",
    "GraphTopology",
    "MasterForensicReport",
    "OriginNetwork",
    "ProtocolForensics",
    "SuspiciousURL",
    "ThreatIntent",
]
