# `POST /api/analyze` contract

The frontend sends the selected evidence file as `multipart/form-data` using the field name `file`.

**Endpoint**

```text
POST ${NEXT_PUBLIC_API_URL}/api/analyze
```

`NEXT_PUBLIC_API_URL` defaults to `http://127.0.0.1:8000`.

## Request

```text
Content-Type: multipart/form-data

file: <.eml or .msg evidence file>
```

## Successful response

The response must be a JSON object matching `app/types/forensic.ts` (`ForensicReport`).

```json
{
  "case_id": "CASE-001",
  "evidence": {
    "filename": "suspicious.eml",
    "sha256": "<64-character SHA-256>",
    "ingestion_timestamp": "2026-08-30T12:00:00Z"
  },
  "protocol_forensics": {
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "domain_alignment": {
      "from_domain": "example.com",
      "return_path_domain": "mail.example.net",
      "reply_to_domain": null,
      "is_aligned": false
    }
  },
  "origin_network": {
    "ip": "203.0.113.10",
    "country": "IN",
    "city": "New Delhi",
    "latitude": 28.6139,
    "longitude": 77.209,
    "asn": "AS64500",
    "org": "Example Network",
    "is_datacenter": true,
    "is_vpn_tor": false,
    "domain_entropy": 3.2,
    "typosquat_target": "example.com",
    "edit_distance": 1
  },
  "threat_intent": {
    "primary_intent": "credential_harvesting",
    "risk_score": 85,
    "urgency_score": 78,
    "flagged_coercion_cues": [],
    "suspicious_urls": []
  },
  "attachment_forensics": [],
  "graph_topology": {
    "nodes": [],
    "edges": [],
    "campaign_cluster_id": null
  },
  "chain_of_custody": []
}
```

## Required vs optional

### Required top-level fields

All of these are required:

- `case_id`
- `evidence`
- `protocol_forensics`
- `origin_network`
- `threat_intent`
- `attachment_forensics`
- `graph_topology`
- `chain_of_custody`

### Required nested fields

The frontend validates the fields needed by the TypeScript contract before it calls `onComplete`.

- Evidence: `filename`, `sha256`, `ingestion_timestamp`
- Protocol: `spf`, `dkim`, `dmarc`, `domain_alignment`
- Domain alignment: `from_domain`, `return_path_domain`, `is_aligned`
- Origin network: `ip`, `country`, `city`, `latitude`, `longitude`, `asn`, `org`, `is_datacenter`, `is_vpn_tor`, `domain_entropy`
- Threat intent: `primary_intent`, `risk_score`, `urgency_score`, `flagged_coercion_cues`, `suspicious_urls`
- Graph: `nodes`, `edges`
- Chain of custody: each entry contains `sequence`, `timestamp`, `action`, `actor`, `prev_hash`, `entry_hash`

### Optional fields

These are optional in `app/types/forensic.ts` and may be `null`:

- `protocol_forensics.domain_alignment.reply_to_domain`
- `origin_network.typosquat_target`
- `origin_network.edit_distance`
- `graph_topology.campaign_cluster_id`

## Current forensic stage coverage

The current backend integration supplies:

1. **Ingestion / evidence hashing** — implemented.
2. **Transit hop tracing / origin telemetry** — implemented.
3. **Authentication verification and domain alignment** — implemented.
4. **GeoIP enrichment** — implemented.
5. **Stage 3–5 advanced analysis** — placeholder in the current backend. The frontend must not invent MITRE technique IDs, NLP confidence values, malicious attachment conclusions, or raw-header contents that the API did not return.

The UI labels these areas as pending/placeholder where applicable.

## Error responses

Non-2xx responses are treated as backend errors. A JSON response may provide a string `detail` field, which is displayed to the user.

The frontend also rejects a successful HTTP response if its JSON does not match the `ForensicReport` shape.

## Timeout and offline behavior

The frontend aborts `/api/analyze` after 30 seconds and shows a backend-unreachable/offline/timeout error instead of loading an invalid or incomplete report.

Preview mode is separate from the live contract: opening the app with `?preview=1` loads the bundled `mockForensicReport` and displays an explicit **PREVIEW MODE** indicator.
