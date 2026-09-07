# SPECTRE.DFIR Frontend

## Quick preview (no backend needed)

1. Open a terminal in this folder.
2. Run `npm install`.
3. Run `npm run dev`.
4. Open http://localhost:3000/?preview=1 to see the full forensic console using local preview data.

Open http://localhost:3000/ for the normal landing page.

## Backend-connected mode

Create `.env.local` from `.env.local.example` if your backend is not on the default address.

Default API: `http://127.0.0.1:8000`

Start the FastAPI backend first, then run `npm run dev`.

The Analyze Evidence button sends the selected file to `POST /api/analyze`.
