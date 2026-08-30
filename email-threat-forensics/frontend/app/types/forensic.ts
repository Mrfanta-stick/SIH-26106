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
    domain_alignment: {
      from_domain: string;
      return_path_domain: string;
      reply_to_domain?: string | null;
      is_aligned: boolean;
    };
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
    suspicious_urls: Array<{
      anchor_text: string;
      destination: string;
      is_mismatch: boolean;
    }>;
  };
  attachment_forensics: Array<{
    filename: string;
    detected_magic: string;
    risk: string;
  }>;
  graph_topology: {
    nodes: Array<{
      id: string;
      label: string;
      type: string;
    }>;
    edges: Array<{
      source: string;
      target: string;
      protocol: string;
      latency: string;
    }>;
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
