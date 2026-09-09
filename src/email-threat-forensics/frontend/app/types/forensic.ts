export const API_BASE =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export interface DomainAlignment {
  from_domain: string;
  return_path_domain: string;
  reply_to_domain?: string | null;
  is_aligned: boolean;
}

export interface SuspiciousURL {
  anchor_text: string;
  destination: string;
  is_mismatch: boolean;
  domain?: string;
}

export interface AttachmentReport {
  filename: string;
  detected_magic: string;
  risk: string;
  size_bytes?: number | null;
  sha256?: string | null;
  virustotal_scan?: Record<string, unknown> | null;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  ip?: string;
  suspicious?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  protocol: string;
  latency: string;
  auth_status?: "pass" | "fail" | "softfail" | "none" | string;
}

export interface ForensicReport {
  case_id: string;
  evidence: {
    filename: string;
    sha256: string;
    ingestion_timestamp: string;
  };
  protocol_forensics: {
    spf: string;
    dkim: string;
    dmarc: string;
    domain_alignment: DomainAlignment;
  };
  origin_network: {
    ip: string;
    country: string;
    city: string;
    latitude: number;
    longitude: number;
    asn: string;
    org: string;
    is_datacenter: boolean;
    is_vpn_tor: boolean;
    domain_entropy: number;
    typosquat_target?: string | null;
    edit_distance?: number | null;
  };
  threat_intent: {
    primary_intent: string;
    risk_score: number;
    urgency_score: number;
    flagged_coercion_cues: string[];
    suspicious_urls: SuspiciousURL[];
  };
  attachment_forensics: AttachmentReport[];
  graph_topology: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    campaign_cluster_id?: string | null;
  };
  chain_of_custody: Array<{
    sequence: number;
    timestamp: string;
    action: string;
    actor: string;
    prev_hash: string;
    entry_hash: string;
  }>;
}

export function formatApiError(payload: unknown, status: number): string {
  const detail =
    payload && typeof payload === "object" && "detail" in payload
      ? (payload as { detail: unknown }).detail
      : undefined;

  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && "msg" in item) {
          return String((item as { msg: unknown }).msg);
        }
        return JSON.stringify(item);
      })
      .filter(Boolean);
    if (messages.length) return messages.join("; ");
  }
  return `API request failed (${status})`;
}
