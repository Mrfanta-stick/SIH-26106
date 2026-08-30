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
    country: "Netherlands",
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
      },
    ],
  },
  attachment_forensics: [
    {
      filename: "invoice_update.pdf.exe",
      detected_magic: "PE32 Executable (GUI) Intel 80386",
      risk: "CRITICAL_EXTENSION_SPOOF",
    },
  ],
  graph_topology: {
    nodes: [
      { id: "node-1", label: "Origin: 194.26.29.112", type: "untrusted" },
      { id: "node-2", label: "MTA: relay.attacker.com", type: "relay" },
      { id: "node-3", label: "Destination: mx.victim.com", type: "trusted" },
    ],
    edges: [
      { source: "node-1", target: "node-2", protocol: "ESMTPS", latency: "1.2s" },
      { source: "node-2", target: "node-3", protocol: "SMTPS", latency: "0.3s" },
    ],
    campaign_cluster_id: "CAMP-NL-FINANCE",
  },
  chain_of_custody: [
    {
      sequence: 1,
      timestamp: "2026-08-27T10:45:00Z",
      action: "EVIDENCE_INGESTED",
      actor: "SOC_Analyst_1",
      prev_hash: "GENESIS_BLOCK",
      entry_hash: "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
    },
  ],
};