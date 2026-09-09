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
- Deployment: Cloud

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

## 8. Final Presentation

Keep your final SIH presentation in the repository whenever the file size allows it.

See [submission/PRESENTATION.md](submission/PRESENTATION.md) for the required format.

If the PPT is too large for GitHub, use Google Drive/OneDrive and put the accessible viewer link in `submission/PRESENTATION.md`.

## 9. Demo Video

A demo video is **optional**, but recommended.

Add the YouTube/Google Drive link in [submission/DEMO.md](submission/DEMO.md).

## 10. Screenshots / Prototype Photos

Add important screenshots or hardware/prototype photos to:

`assets/screenshots/`

See [assets/screenshots/README.md](assets/screenshots/README.md) for examples and naming conventions.

## 11. Installation

```bash
git clone git@github.com:Mrfanta-stick/SIH-26106.git
cd email-threat-forensics/backend
pip install -r requirements.txt
```

## 12. Run

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

## 13. Future Scope

Describe realistic improvements or extensions that can be made to the project.
