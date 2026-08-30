"""
Unified Pydantic V2 Master Contract for the DFIR platform.

Every backend pipeline function MUST return the designated model slice declared
in this module. Stages outside this module's contract — for example Stage 3:
intent, Stage 4: attribution and Stage 5: custody — must populate the
corresponding fields of MasterForensicReport after importing the
models defined here.

Contract map (module -> model slice)

    app.network.ingest -> EvidenceMetadata
    app.network.auth_verifier -> ProtocolForensics
    app.network.domain_geo -> OriginNetwork
    app.intent.semantic_engine -> ThreatIntent
    app.attribution.attachment -> List[AttachmentReport]
    app.attribution.cluster_graph -> GraphTopology
    app.custody.audit_ledger -> List[ChainOfCustodyEntry]
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


# Configuration shared across every model in the contract.

# We standardise on extra="forbid" so the contract cannot be silently
# extended at runtime — any drift will surface as a ValidationError during
# CI rather than as opaque dictionary keys leaking into the JSON payload.
_BASE_CONFIG: ConfigDict = ConfigDict(
    extra="forbid",
    frozen=False,
    populate_by_name=True,
    str_strip_whitespace=True,
)


class EvidenceMetadata(BaseModel):
    # Provenance metadata captured at ingestion time.
    model_config = _BASE_CONFIG
    filename: str = Field(
        description="Original filename as supplied by the operator / frontend.",
    )
    sha256: str = Field(
        description="Lowercase hex-encoded SHA-256 of the raw submission bytes.",
    )
    ingestion_timestamp: str = Field(
        description="ISO-8601 UTC timestamp marking the moment of intake.",
    )


class DomainAlignment(BaseModel):
    # RFC 5322 envelope-vs-header domain alignment evaluation.

    model_config = _BASE_CONFIG
    from_domain: str = Field(
        description="Domain extracted from the header ``From:`` address.",
    )
    return_path_domain: str = Field(
        description="Domain extracted from the envelope ``Return-Path:`` header.",
    )
    reply_to_domain: Optional[str] = Field(
        default=None,
        description="Domain extracted from the optional ``Reply-To:`` header.",
    )
    is_aligned: bool = Field(
        description=(
            "True when the From domain and Return-Path domain share the same "
            "registered (eTLD+1) suffix — i.e. relaxed alignment passes."
        ),
    )


class ProtocolForensics(BaseModel):
    # Authentication framework verdicts lifted from Authentication-Results.

    model_config = _BASE_CONFIG
    spf: str = Field(
        description="SPF verdict — one of PASS, FAIL, SOFTFAIL, NONE, TEMPERROR.",
    )
    dkim: str = Field(
        description="DKIM verdict — one of PASS, FAIL, NONE, TEMPERROR.",
    )
    dmarc: str = Field(
        description="DMARC verdict — one of PASS, FAIL, NONE, TEMPERROR.",
    )
    domain_alignment: DomainAlignment


class OriginNetwork(BaseModel):
    # Geo-enriched view of the originating SMTP / submission hop.

    model_config = _BASE_CONFIG

    ip: str = Field(description="Public IPv4/IPv6 address of the earliest hop.")
    country: str = Field(description="ISO-3166-1 alpha-2 country code, or 'XX'.")
    city: str = Field(description="City name as recorded by MaxMind GeoLite2.")
    latitude: float = Field(description="Decimal degrees north, 0.0 if unknown.")
    longitude: float = Field(description="Decimal degrees east, 0.0 if unknown.")
    asn: str = Field(description="Autonomous System Number, e.g. 'AS15169'.")
    org: str = Field(description="ASN organisation name recorded by MaxMind.")
    is_datacenter: bool = Field(
        description="True when the ASN belongs to a known hosting/datacenter provider.",
    )
    is_vpn_tor: bool = Field(
        description="True when the IP is flagged as VPN, Tor or anonymous relay.",
    )
    domain_entropy: float = Field(
        description="Shannon entropy (bits/char) of the sender's domain string.",
    )
    typosquat_target: Optional[str] = Field(
        default=None,
        description="Closest legitimately-spoofed brand domain, if any.",
    )
    edit_distance: Optional[int] = Field(
        default=None,
        description="Levenshtein edit distance to ``typosquat_target``.",
    )


class SuspiciousURL(BaseModel):
    # An anchor whose visible text and href target disagree.

    model_config = _BASE_CONFIG

    anchor_text: str = Field(description="Visible text inside the ``<a>`` tag.")
    destination: str = Field(description="Resolved href / hyperlink target.")
    is_mismatch: bool = Field(
        description="True when anchor text hosts a different domain than the destination.",
    )


class ThreatIntent(BaseModel):
    # Group 3 semantic & linguistic threat verdict.

    model_config = _BASE_CONFIG
    primary_intent: str = Field(
        description=(
            "One of BENIGN, BEC_WIRE_FRAUD, PAYROLL_DIVERT, "
            "CREDENTIAL_HARVEST, EXTORTION."
        ),
    )
    risk_score: int = Field(
        ge=0, le=100,
        description="Composite numeric risk score in the closed range [0, 100].",
    )
    urgency_score: float = Field(
        ge=0.0, le=1.0,
        description="Normalised coercion / time-pressure score in [0.0, 1.0].",
    )
    flagged_coercion_cues: List[str] = Field(
        default_factory=list,
        description="Sentence-level snippets classified as coercion.",
    )
    suspicious_urls: List[SuspiciousURL] = Field(
        default_factory=list,
        description="Anchor / href mismatches harvested from the HTML body.",
    )


class AttachmentReport(BaseModel):
    # Static analysis verdict for a single attachment.

    model_config = _BASE_CONFIG

    filename: str = Field(description="Attachment filename as transmitted.")
    detected_magic: str = Field(
        description="libmagic / MIME-type signature observed in the bytes.",
    )
    risk: str = Field(
        description=(
            "Static triage label — e.g. BENIGN, ZIP_BOMB, "
            "STAGED_PAYLOAD, MACRO_DOCUMENT, UNKNOWN."
        ),
    )


class GraphNode(BaseModel):
    # A node in the React Flow campaign-cluster topology.

    model_config = _BASE_CONFIG

    id: str = Field(description="Stable, unique node identifier (e.g. email, IP, ASN).")
    label: str = Field(description="Human-readable node label.")
    type: str = Field(
        description="Node type discriminator — e.g. 'sender', 'ip', 'asn', 'domain'.",
    )


class GraphEdge(BaseModel):
    # A directed relationship between two graph nodes.

    model_config = _BASE_CONFIG

    source: str = Field(description="Source :class:`GraphNode` ``id``.")
    target: str = Field(description="Target :class:`GraphNode` ``id``.")
    protocol: str = Field(
        description="Transport protocol — e.g. 'smtp', 'https', 'mx'.",
    )
    latency: str = Field(
        description="Observed or estimated propagation delay, e.g. '12ms'.",
    )


class GraphTopology(BaseModel):
    # Full React Flow topology payload.

    model_config = _BASE_CONFIG

    nodes: List[GraphNode] = Field(
        default_factory=list,
        description="All graph nodes participating in the case.",
    )
    edges: List[GraphEdge] = Field(
        default_factory=list,
        description="All directed relationships among the nodes.",
    )
    campaign_cluster_id: Optional[str] = Field(
        default=None,
        description="Stable identifier of the cluster this case joins, if any.",
    )


class ChainOfCustodyEntry(BaseModel):
    # One append-only entry in the SHA-256 hash-chained audit ledger.

    model_config = _BASE_CONFIG

    sequence: int = Field(ge=0, description="Strictly monotonic ledger index.")
    timestamp: str = Field(
        description="ISO-8601 UTC timestamp of the recorded action.",
    )
    action: str = Field(description="Human-readable ledger action label.")
    actor: str = Field(description="System or user credited with the action.")
    prev_hash: str = Field(
        description="Hex SHA-256 of the previous entry, or '0'*64 for genesis.",
    )
    entry_hash: str = Field(
        description="Hex SHA-256 of ``sequence|timestamp|action|actor|prev_hash``.",
    )


class MasterForensicReport(BaseModel):
    # The single Pydantic V2 instance exchanged with the Next.js frontend.

    model_config = _BASE_CONFIG

    case_id: str = Field(
        description="Stable case identifier (UUID4 by default).",
    )
    evidence: EvidenceMetadata
    protocol_forensics: ProtocolForensics
    origin_network: OriginNetwork
    threat_intent: ThreatIntent
    attachment_forensics: List[AttachmentReport] = Field(
        default_factory=list,
        description="Per-attachment static triage results.",
    )
    graph_topology: GraphTopology
    chain_of_custody: List[ChainOfCustodyEntry] = Field(
        default_factory=list,
        description="Append-only audit trail of every custody-relevant action.",
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
