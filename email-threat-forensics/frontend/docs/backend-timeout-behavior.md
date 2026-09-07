# Backend timeout and fail-fast behavior

The forensic scanner treats the backend response as authoritative.

- If the browser is offline, analysis fails immediately.
- A lightweight `/docs` connectivity probe uses a 2.5 second limit during local development.
- A reachable backend that accepts the analysis request has a hard 30 second request timeout.
- HTTP errors and malformed/non-JSON responses are surfaced to the user.
- The scanner stops its progress animation on failure.
- The error state remains visible with **Retry analysis** and **Close** controls.
- `NEXT_PUBLIC_API_URL` is used as the backend base URL, falling back to `http://127.0.0.1:8000`.
- Successful `/api/analyze` responses are runtime-validated before `onComplete()` is called.

The existing dark SPECTRE.DFIR styling and FastAPI `/api/analyze` integration are retained.
