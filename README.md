# SIH 2026 Project for team, The Mentalists.

## 1. Project Information

- **Project Title:** SpectreDFIR – Smart Email Threat Detection.
- **PS ID:** 26106
- **PS Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
- **Category:** Software
- **Theme:** Blockchain and Cybersecurity

## 2. Problem Statement

An AI-powered email forensics platform that detects fraudulent emails, analyzes their complete technical structure and transmission path, and provides actionable intelligence to trace malicious origins, infrastructure, and potential threat actors.

## 3. Proposed Solution

SpectreDFIR requires the user to upload a `.eml`/`.msg` file. 
- **Ingestion** — Drag-and-drop Next.js dashboard for raw `.eml` / `.msg` file uploads
- **Origin Tracing** — Unfolds `Received:` headers, filters private subnets, traces back to earliest public origin IP
- **IP Enrichment** — Local GeoLite2 lookup for coordinates, ASN ownership, and datacenter/VPN classification
- **Semantic Scoring** — Transformer embeddings score email body for intent, urgency, and coercion
- **Attachment Triage** — In-memory magic byte inspection to detect extension spoofing and container smuggling, paired with cached VirusTotal hash reputation (no execution)
- **Audit Ledger** — Append-only, SHA-256 hash-chained log for provable non-tampering
- **Dossier Generation** — Auto-generated PDF report: ledger hash, IP-hop map, header timeline, custody table


## 4. Key Features

* AI-powered email threat intent detection
* Semantic NLP-based email analysis
* Phishing, fraud, and impersonation detection
* Threat risk scoring (0–100)
* Urgency and coercion detection
* Social engineering analysis
* Suspicious URL detection and analysis
* Invisible/hidden text detection
* `.eml`/`.msg` email forensic analysis
* Ingestion — Drag-and-drop dashboard for raw `.eml` / `.msg` file uploads
* Origin Tracing — Unfolds `Received:` headers to trace back to the earliest public origin IP
* IP Enrichment — Offline GeoLite2 profiling for ASN, coordinates, and VPN/Datacenter classification
* Attachment Triage — In-memory magic byte inspection to detect extension spoofing and container smuggling, paired with cached VirusTotal hash reputation
* Campaign Clustering — Links incidents across cases via shared IP subnets, nameservers, and DKIM keys (For future implementation)
* Cryptographic audit ledger and chain of custody
* Evidence tampering detection
* Automated PDF forensic report generation
* Explainable threat intelligence results

## 5. Technology Stack

- Frontend: Next.js
- Backend: Python
- Machine Learning Models: [`Sentence Transformer (all-MiniLM-L6-v2)`](https://sbert.net/), [`spaCy Blank English Model`](https://spacy.io/models/en)

## 6. Architecture

See [docs/architecture.md](docs/architecture.md).

```text
 User Uploads .eml / .msg on Next.js UI
                        │  
                        V (POST /api/analyze)

* Compute SHA-256 Hash
* Extract Origin IP, SPF/DKIM/DMARC, GeoIP, ASN, Shannon Entropy
* Produce partial metadata dictionary
                        │
                        V (Internal Python Pipeline)

* Extract body text → compute BEC intent & urgency scores
* Scan attachments → format React Flow graph & cluster campaign
* Append record to hash-chained custody ledger in PostgreSQL (For future)
                        │
                        V (HTTP 200 Response)

* Render Threat Map, Hop Graph, Recharts Gauges, and Custody Timeline
* Enable 1-click "Download Law Enforcement PDF Dossier"
```

## 7. Repository Structure

```text
email-threat-forensics/
├── src/
│   └── email-threat-forensics/
│       ├── backend/
│       │   └── app/
│       │       ├── attribution/
│       │       │   ├── __init__.py
│       │       │   ├── attachment_parser.py
│       │       │   ├── graph_builders.py
│       │       │   └── master_builder.py
│       │       ├── custody/
│       │       │   ├── audit_ledger.py
│       │       │   └── pdf_generator.py
│       │       ├── data/
│       │       │   ├── GeoLite2-ASN.mmdb
│       │       │   └── GeoLite2-City.mmdb
│       │       ├── intent/
│       │       │   ├── __init__.py
│       │       │   ├── extractor.py
│       │       │   ├── intent.py
│       │       │   └── pattern.py
│       │       ├── network/
│       │       │   ├── __init__.py
│       │       │   ├── auth_verifier.py
│       │       │   ├── domain_geo.py
│       │       │   ├── hop_tracer.py
│       │       │   └── ingest.py
│       │       ├── schemas/
│       │       │   ├── __init__.py
│       │       │   └── forensic_report.py
│       │       └── main.py
│       └── frontend/
│           ├── app/
│           │   ├── components/
│           │   │   ├── AIVeridict.tsx
│           │   │   ├── AttachmentTriage.tsx
│           │   │   ├── CaseHeader.tsx
│           │   │   ├── ChainOfCustody.tsx
│           │   │   ├── CyberHoloCore3D.tsx
│           │   │   ├── Dropzone.tsx
│           │   │   ├── ForensicScannerModal.tsx
│           │   │   ├── HopGraph.tsx
│           │   │   ├── MitreMatrix.tsx
│           │   │   ├── RawHeaders.tsx
│           │   │   ├── ThreatGauges.tsx
│           │   │   └── ThreatMap.tsx
│           │   ├── types/
│           │   │   └── forensic.ts
│           │   ├── favicon.ico
│           │   ├── globals.css
│           │   ├── layout.tsx
│           │   └── page.tsx
│           ├── scripts/
│           │   ├── lint.mjs
│           │   └── .env.local.example
│           ├── .github/
│           ├── .gitignore
│           ├── package-lock.json
│           └── package.json
├── postcss.config.mjs
├── tsconfig.json
├── .gitignore
├── README.md
├── requirements.txt
```

## 10. Installation

```bash
git clone git@github.com:Mrfanta-stick/SIH-26106.git
cd email-threat-forensics/backend
pip install -r requirements.txt
```

## 11. Run

To run backend server
```bash
cd "SIH 26106/src/email-threat-forensics/backend"
python -m uvicorn app.main:app --reload
```

To run frontend (* Ensure Node.js and NPM are installed)
```bash
cd "SIH 26106/src/email-threat-forensics/frontend"
npm run dev
```

## 12. Future Scope

1. **Cross-Case Campaign Correlation & Graph Clustering**
   Transition from isolated single-email triage to global campaign intelligence using a graph database (e.g., Neo4j).
   Automatically cluster independent cases under a unified `campaign_cluster_id` by correlating shared infrastructure attributes: identical DKIM key selectors, origin `/24` subnets, registrar data, and matching attachment SHA-256 hashes across multiple targets.

2. **Dynamic Malware Sandboxing (CAPE / Cuckoo Integration)**
   Expand beyond Stage 4 static magic-byte triage by orchestrating automated detonation of suspicious payloads within an isolated, headless VM or containerized sandbox.
   Capture runtime behavioral indicators: process tree injection, Windows API hooking, registry modifications, and outbound Command & Control (C2) network beacons.

3. **Visual Threat Parser & "Quishing" (QR Phishing) Detection**
   Integrate lightweight OCR (Tesseract / Vision models) and automated computer vision parsing to counter evasive attacks where threat text is embedded inside attached images or flattened PDFs.
   Detect and decode embedded QR codes ("quishing") and evaluate the extracted destination target through the Stage 3 URL de-obfuscation pipeline.

4. **Mailbox Sensors & Automated SIEM/SOAR Ingestion**
   Ingest evidence automatically using live webhooks and connectors (Microsoft Graph API, Google Workspace API, and IMAP sensor daemons) rather than relying solely on manual analyst `.eml` uploads.
   Stream structured IOCs directly into SOC platforms (Splunk, Microsoft Sentinel, Cortex XSOAR) formatted as standardized STIX 2.1 bundles over TAXII feeds.

5. **RFC 3161 Cryptographic Timestamping & Hardware Custody**
   Upgrade the current SHA-256 software hash chain into court-certified digital evidence by binding block generation to an RFC 3161 compliant Trusted Timestamping Authority (TSA).
   Integrate Hardware Security Modules (HSMs) or KMS-managed asymmetric signing keys to guarantee immutable non-repudiation under ISO/IEC 27037 and national digital evidence admissibility standards.

6. **Persistent Forensic Case Management & Retention**
   Replace the volatile in-memory cache with an enterprise database (MongoDB with TimescaleDB) to maintain historical audit ledgers, case search indexing, and role-based access control (RBAC) across forensic investigator teams.
