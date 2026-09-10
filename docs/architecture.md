# System Architecture

## High-level flow

```text
User Uploads .eml/.msg
        │
        ▼
[Next.js Frontend]
        │
        │ POST /api/analyze
        ▼
[Backend API]
        │
        ├── Compute SHA-256
        ├── Extract Email Metadata
        │      ├── IP Addresses
        │      ├── SPF / DKIM / DMARC
        │      ├── GeoIP / ASN
        │      └── Shannon Entropy
        │
        ▼
[ML Pipeline]
        ├── Text Preprocessing
        ├── Intent Classification
        ├── Urgency Scoring
        └── Risk Assessment
        │
        ▼
[Forensic Analysis]
        ├── Attachment Scanning
        ├── React Flow Hop Graph
        └── Campaign Clustering
        │
        ▼
[PostgreSQL]
        └── Hash-Chained Custody Ledger
        │
        ▼
[Frontend Visualization]
        ├── Threat Map
        ├── Hop Graph
        ├── Risk Gauges
        └── Custody Timeline
        │
        ▼
[PDF Dossier Generator]
        │
        ▼
Law Enforcement PDF Dossier
```

## Components

## Backend Architecture

The backend is built in **Python** and serves as the core processing engine for SpectreDFIR. It handles email ingestion, forensic analysis, threat detection, and report generation.

### **Core Components**

#### **1. API Layer (`app/main.py`)**
- **Framework**: FastAPI (ASGI)
- **Endpoints**:
  - `POST /api/analyze` – Primary endpoint for `.eml`/`.msg` file uploads.
  - `GET /api/report/{case_id}` – Retrieves generated forensic reports.
  - `GET /api/ledger` – Fetches audit ledger entries (hash-chained).
- **Features**:
  - File validation (MIME type, size limits).
  - SHA-256 hashing for integrity checks.
  - Asynchronous task queue for heavy computations (e.g., ML inference, PDF generation).

#### **2. Email Ingestion & Parsing (`app/network/ingest.py`)**
- **Functionality**:
  - Parses `.eml` (RFC 5322) and `.msg` (Outlook) formats.
  - Extracts headers, body, attachments, and metadata.
  - Normalizes character encoding (UTF-8, base64, quoted-printable).
- **Key Modules**:
  - `email` (Python standard library) for `.eml`.
  - `extract_msg` for `.msg` (Outlook files).

#### **3. Origin Tracing (`app/network/hop_tracer.py`)**
- **Functionality**:
  - Unfolds `Received:` headers to reconstruct the email’s transmission path.
  - Filters private/non-routable IPs (RFC 1918, RFC 4193, etc.).
  - Identifies the **earliest public origin IP** (source of the email).
- **Output**:
  - List of IP hops with timestamps.
  - Geolocated coordinates (latitude/longitude) for each hop.

#### **4. IP Enrichment (`app/network/domain_geo.py`)**
- **Data Sources**:
  - **GeoLite2-City.mmdb**: Offline database for city-level geolocation.
  - **GeoLite2-ASN.mmdb**: Offline database for ASN (Autonomous System Number) and ISP lookup.
- **Features**:
  - Classifies IPs as **VPN, Datacenter, or Residential**.
  - Flags known malicious IPs (via cached threat intelligence).

#### **5. Attachment Triage (`app/attribution/attachment_parser.py`)**
- **Functionality**:
  - **Magic Byte Inspection**: Detects file type mismatches (e.g., `.pdf` claiming to be `.jpg`).
  - **Container Smuggling Detection**: Checks for embedded files in archives (ZIP, RAR, etc.).
  - **VirusTotal Integration**:
    - Computes SHA-256 hashes of attachments.
    - Queries VirusTotal’s cached API for reputation (no file execution).
- **Output**:
  - Risk score per attachment (0–100).
  - List of suspicious files with reasoning.

#### **6. Intent & Semantic Analysis (`app/intent/`)**
- **Models**:
  - **Sentence Transformer (`all-MiniLM-L6-v2`)**: Computes semantic embeddings for intent classification.
  - **spaCy**: Tokenization, sentence segmentation, and NLP preprocessing.
- **Pipeline**:
  1. **Text Extraction**: Strips HTML, decodes base64, and normalizes text.
  2. **Intent Classification**:
     - Cosine similarity against predefined intent prototypes (e.g., phishing, coercion, urgency).
     - Temperature-scaled softmax for probability distribution.
  3. **Urgency Scoring**:
     - Semantic similarity + regex patterns (e.g., "urgent", "immediately", "ASAP").
  4. **Risk Aggregation**:
     - Weighted sum of **Intent Risk (35%)**, **Suspicious URLs (25%)**, **Urgency (15%)**, **Coercion Cues (15%)**, **Invisible Text (10%)**.

#### **7. Audit Ledger (`app/custody/audit_ledger.py`)**
- **Purpose**: Immutable, tamper-proof log for chain of custody.
- **Implementation**:
  - **Hash-Chaining**: Each entry includes the SHA-256 hash of the previous entry.
  - **PostgreSQL Backend** (Future): Persistent storage for ledger entries.
- **Fields**:
  - Timestamp (ISO 8601).
  - Case ID (UUID).
  - Action (e.g., "File Uploaded", "Analysis Complete").
  - SHA-256 hash of the current state.

#### **8. PDF Dossier Generator (`app/custody/pdf_generator.py`)**
- **Library**: `reportlab` (Python PDF generation).
- **Sections**:
  - **Case Metadata**: Hash, timestamp, analyst notes.
  - **Threat Summary**: Risk score, intent, urgency.
  - **IP Hop Map**: Visual graph of transmission path.
  - **Header Timeline**: Chronological `Received:` headers.
  - **Custody Table**: Audit ledger entries.
  - **Attachment Analysis**: Triage results.
- **Output**: Downloadable PDF for law enforcement.

#### **9. Graph Builders (`app/attribution/graph_builders.py`)**
- **Purpose**: Constructs interactive graphs for the frontend.
- **Outputs**:
  - **Hop Graph**: Nodes = IP hops, Edges = transmission path (React Flow compatible).
  - **Campaign Clustering** (Future): Links cases via shared IPs, DKIM keys, or subnets.

#### **10. Authentication Verifier (`app/network/auth_verifier.py`)**
- **Functionality**:
  - Validates SPF, DKIM, and DMARC records.
  - Checks for **email spoofing** (e.g., `From:` domain ≠ `Return-Path`).

---

## Frontend Architecture

The frontend is built with **Next.js (App Router)** and provides an interactive dashboard for uploading emails, visualizing threats, and generating reports.

### **Core Components**

#### **1. Entry Point (`app/page.tsx`)**
- **Layout**: Main dashboard with drag-and-drop zone.
- **State Management**: React Context API for global state (e.g., analysis results).
- **Routing**: Client-side navigation (Next.js `useRouter`).

#### **2. Drag-and-Drop Upload (`app/components/Dropzone.tsx`)**
- **Library**: `react-dropzone`.
- **Features**:
  - Supports `.eml` and `.msg` files.
  - Real-time validation (file type, size < 50MB).
  - Visual feedback (loading spinner, success/error toasts).
- **Flow**:
  1. User drops file → Preview filename.
  2. Auto-upload to `/api/analyze`.
  3. Display results in **ForensicScannerModal**.

#### **3. Forensic Scanner Modal (`app/components/ForensicScannerModal.tsx`)**
- **Purpose**: Central hub for analysis results.
- **Tabs**:
  - **Overview**: Threat score, intent, urgency.
  - **Headers**: Raw email headers (`RawHeaders` component).
  - **Attachments**: Triage results (`AttachmentTriage` component).
  - **Hop Graph**: Interactive transmission path (`HopGraph` component).
  - **Threat Map**: Geolocated IPs (`ThreatMap` component).
  - **Custody**: Audit ledger (`ChainOfCustody` component).

#### **4. Threat Visualization**
##### **A. Threat Gauges (`app/components/ThreatGauges.tsx`)**
- **Library**: `recharts`.
- **Metrics**:
  - **Risk Score**: 0–100 (radial gauge).
  - **Urgency Score**: 0–1 (linear gauge).
  - **Intent Confidence**: % breakdown (bar chart).
- **Styling**: Color-coded (red = high risk, green = low risk).

##### **B. Threat Map (`app/components/ThreatMap.tsx`)**
- **Library**: `leaflet` + `react-leaflet`.
- **Features**:
  - Plots IP hops on a world map.
  - Tooltips with IP, ASN, and geolocation details.
  - Zoom/pan to inspect clusters.

##### **C. Hop Graph (`app/components/HopGraph.tsx`)**
- **Library**: `reactflow`.
- **Features**:
  - Nodes: IP addresses (color-coded by risk).
  - Edges: Transmission path (directional arrows).
  - Interactive: Click nodes to see details (e.g., GeoIP, ASN).

##### **D. MITRE Matrix (`app/components/MitreMatrix.tsx`)**
- **Purpose**: Maps detected threats to MITRE ATT&CK tactics/techniques.
- **Data**: Static JSON mapping (e.g., "Phishing" → **T1566**).
- **Visualization**: Grid or heatmap.

#### **5. Attachment Triage (`app/components/AttachmentTriage.tsx`)**
- **Features**:
  - Lists all attachments with:
    - Filename, type (magic byte vs. extension).
    - SHA-256 hash.
    - VirusTotal reputation (if available).
    - Risk score (0–100).
  - Color-coded: Red (malicious), Yellow (suspicious), Green (safe).

#### **6. Raw Headers (`app/components/RawHeaders.tsx`)**
- **Purpose**: Displays parsed email headers in a collapsible tree.
- **Features**:
  - Syntax highlighting for `Received:`, `From:`, `SPF:`, etc.
  - Copy-to-clipboard button.

#### **7. Chain of Custody (`app/components/ChainOfCustody.tsx`)**
- **Purpose**: Displays the immutable audit ledger.
- **Features**:
  - Table with columns: **Timestamp**, **Action**, **Hash**, **Analyst**.
  - Verifiable: Each row’s hash depends on the previous row.

#### **8. AI Verdict (`app/components/AIVeridict.tsx`)**
- **Purpose**: Summarizes the AI’s analysis in plain English.
- **Features**:
  - **Intent**: "This email is **highly likely to be phishing** (92% confidence)."
  - **Urgency**: "Contains **time-sensitive language** (e.g., 'Act now!')."
  - **Recommendations**: "Do not click links. Report to IT."

#### **9. Case Header (`app/components/CaseHeader.tsx`)**
- **Purpose**: Displays metadata for the current analysis.
- **Fields**:
  - Case ID (UUID).
  - Upload timestamp.
  - Filename.
  - SHA-256 hash (truncated).

#### **10. Cyber Holo Core 3D (`app/components/CyberHoloCore3D.tsx`)**
- **Purpose**: Aesthetic 3D visualization (optional).
- **Library**: `three.js` + `react-three-fiber`.
- **Features**:
  - Animated 3D model (e.g., globe, network nodes).
  - Responds to threat score (e.g., pulses red for high risk).

---



### Machine Learning Pipeline



The intent classification and risk analysis model processes raw email payloads (text and HTML) to quantify intent probabilities, urgency, and overall security risk. The architecture operates through a sequential pipeline of natural language processing (NLP), semantic similarity computations, and weighted aggregation.

```text
Algorithm 1: End-to-End Evaluation Pipeline
Input: Email text, HTML content
Output: Final Intent, Coercion Cues, Urgency Score, Risk Score

1. Extract and preprocess plain text from email and HTML payloads.
2. Segment text into independent sentences using NLP boundaries.
3. Compute sentence-level intent probabilities and identify candidate intents.
4. Aggregate probabilities across all sentences to determine the global Intent.
5. Extract coercion cues by filtering sentences mapped to the final Intent.
6. Compute the Urgency Score using semantic similarity and regex patterns.
7. Compute the Final Risk Score via weighted summation of heuristics.
```

**Sentence-Level Intent Classification**

For each segmented sentence, the model calculates a probability distribution across all predefined intent categories.

1. Compute the cosine similarity between the input sentence vector and the prototype vectors of each category.
2. Retain the maximum cosine similarity score, $S_c$, for each category $c$.
3. Map the cosine similarity to an angular score $A_c$ to linearize the distance metric:

$$
A_c = 1 - \frac{2 \arccos(S_c)}{\pi}
$$
   
5. Apply a temperature-scaled softmax function to convert angular scores into normalized probabilities. To ensure numerical stability, the maximum angular score $A_{max}$ is subtracted:

$$
P_c = \frac{e^{(A_c - A_{max}) / \tau}}{\sum_{i} e^{(A_i - A_{max}) / \tau}}
$$

   where $\tau$ is the temperature parameter.
   
6. Determine the classification threshold $T_{rel}$ relative to the maximum categorical probability for the sentence $P_{max}$:
   
   $$ 
   T_{rel} = \max(0.04, P_{max} \times 0.8) 
   $$
   
7. Assign the category to the sentence as a candidate intent if $P_c > T_{rel}$. This relative threshold permits multi-label classification for sentences demonstrating high confidence across multiple intents.

**Document-Level Intent Aggregation**

To derive the global intent of the document, sentence-level probabilities are aggregated to account for frequency and intensity.

For each category, the final unnormalized probability $P_{final}$ is computed using an asymptotic weighting function:

$$ 
P_{final} = P_{max} + \beta (1 - P_{max})(1 - e^{-\lambda(n-1)}) 
$$

where:
* $P_{max}$: Maximum probability observed for the category across all sentences.
* $n$: Total occurrences where the category exceeded the relative threshold $T_{rel}$.
* $\beta$: Asymptote scaling factor (constant: 0.3).
* $\lambda$: Decay rate (constant: 0.7).

The aggregated values for all categories are subsequently normalized by dividing each by the total sum. The category with the highest aggregated probability is designated as the primary document intent.

**Urgency Score Calculation**

The Urgency Score $\in [0,1]$ evaluates time-sensitive or high-pressure language through a dual-heuristic approach:
* **Semantic Analysis:** Computes the vector similarity between target sentences and known urgency prototypes.
* **Deterministic Pattern Matching:** Utilizes regular expressions to detect explicit, time-constrained vocabulary.
* **Aggregation:** The strongest signals from both the semantic representation and the deterministic match are synthesized into a single normalized scalar.

**Risk Score Aggregation Framework**

The overarching Risk Score $\in [0,1]$ is derived via a linear combination of independent threat vectors.

| Threat Indicator | Weight | Evaluation Mechanism |
| :--- | :--- | :--- |
| **Intent Risk** | 35% | Static risk coefficient mapped directly from the primary predicted document intent. |
| **Suspicious URLs** | 25% | Quantitative thresholding of malicious or obfuscated hyperlinks (capped at a predefined upper bound). |
| **Urgency** | 15% | The continuous output derived from the Urgency Score Calculation. |
| **Coercion Cues** | 15% | Detection of manipulative or threatening semantic structures across the text. |
| **Invisible Text** | 10% | Binary or proportional indicator of hidden DOM elements (e.g., zero-pixel fonts, background-colored text). |
