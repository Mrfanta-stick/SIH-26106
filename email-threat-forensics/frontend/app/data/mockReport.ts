import { ForensicReport } from '../types/forensic';

export const mockForensicReport: ForensicReport = {
  case_id: "CASE-2026-08A",
  evidence: {
    filename: "suspicious_invoice.eml",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ingestion_timestamp: "2026-08-27T10:45:00Z",
  },
  protocol_forensics: {
    spf: "FAIL",
    dkim: "FAIL",
    dmarc: "FAIL",
    domain_alignment: {
      from_domain: "support-microsoft.com",
      return_path_domain: "compromised-relay.ru",
      is_aligned: false,
    },
  },
  origin_network: {
    ip: "194.26.29.112",
    country: "NL",
    city: "Amsterdam",
    latitude: 52.3676,
    longitude: 4.9041,
    asn: "AS49870",
    org: "Alvosec Hosting B.V.",
    is_datacenter: true,
    is_vpn_tor: false,
    domain_entropy: 3.89,
    typosquat_target: "microsoft.com",
    edit_distance: 1,
  },
  threat_intent: {
    primary_intent: "BEC_WIRE_FRAUD",
    risk_score: 92,
    urgency_score: 0.85,
    flagged_coercion_cues: [
      "act within 1 hour",
      "strictly confidential",
    ],
    suspicious_urls: [
      {
        anchor_text: "https://microsoft.com/login",
        destination: "http://194.26.29.112/auth.php",
        is_mismatch: true,
        domain: "194.26.29.112",
      },
    ],
  },
  attachment_forensics: [
    {
      filename: "invoice_update.pdf.exe",
      detected_magic: "PE32 Executable (GUI) Intel 80386",
      risk: "CRITICAL_EXTENSION_SPOOF",
      size_bytes: 245760,
      sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      virustotal_scan: { malicious: 12, suspicious: 3, undetected: 55, harmless: 0 },
    },
  ],
  graph_topology: {
    nodes: [
      { id: "node-1", label: "Origin: 194.26.29.112", type: "origin" },
      { id: "node-2", label: "MTA: relay.attacker.com", type: "mta" },
      { id: "node-3", label: "Destination: mx.victim.com", type: "destination" },
    ],
    edges: [
      { source: "node-1", target: "node-2", protocol: "ESMTPS", latency: "1s" },
      { source: "node-2", target: "node-3", protocol: "SMTPS", latency: "0s" },
    ],
    campaign_cluster_id: "CAMP-NL-FINANCE",
  },
  chain_of_custody: [
    {
      sequence: 0,
      timestamp: "2026-08-27T10:45:00Z",
      action: "EVIDENCE_INTAKE (SHA-256: e3b0c44298fc1c14)",
      actor: "system/ingest",
      prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
      entry_hash: "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
    },
  ],
};
