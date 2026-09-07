# SPECTRE.DFIR frontend ↔ FastAPI connection

The frontend sends the selected `.eml`/`.msg` file as multipart form data to:

`POST ${NEXT_PUBLIC_API_URL}/api/analyze`

If `NEXT_PUBLIC_API_URL` is not set, the frontend defaults to `http://127.0.0.1:8000`.

## Run

1. Start the FastAPI backend from `email-threat-forensics/backend` with your normal environment, for example:
   `uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`
2. Start the Next.js frontend on port 3000.
3. Open the frontend, choose or drag an `.eml`/`.msg` file, then click **Analyze Evidence**.
4. The scanner modal now waits for the real API response. The returned `MasterForensicReport` replaces the empty case and drives the console/ledger views.

## Important backend scope

The supplied backend currently implements ingestion, hop tracing, authentication verification and GeoIP enrichment. Its Stage 3/4/5 fields are placeholders. The frontend therefore avoids inventing MITRE attribution, NLP confidence, malicious attachment verdicts or raw-header contents when those values are not present in the API response.
