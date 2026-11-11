# CyberLens — PERN + JavaScript SIH Prototype

CyberLens is an AI-assisted Email Threat Detection & Digital Forensics platform.

## Stack
- PostgreSQL
- Express.js
- React
- Node.js
- JavaScript (no TypeScript)
- Vite
- Tailwind CSS
- Lucide React
- Recharts
- React Router
- FastAPI AI-service structure

## Run the frontend
Open a terminal inside `frontend`:

```bash
npm install
npm run dev
```

Then open the Vite URL shown in the terminal.

## Run the backend
Open another terminal inside `backend`:

```bash
npm install
npm run dev
```

The API runs on port 4000.

## PostgreSQL
Copy `.env.example` to `.env` and set:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/cyberlens
JWT_SECRET=replace-this-secret
PORT=4000
```

Run `backend/db/schema.sql` in PostgreSQL.

The frontend has a fully functional demo mode, so PostgreSQL is not required just to view the UI.

## Primary judge flow
Landing → Login → Dashboard → New Investigation → Upload demo evidence → Analysis → Result → Forensics → Authentication → SMTP → Threat Graph → Geolocation → Campaign → Evidence → Report.

## Security architecture
Raw evidence and processed analysis are conceptually separated. Uploaded files are treated as untrusted evidence and must never be executed. Production deployment should add isolated parsing workers, encrypted object storage, strict validation, CSP/HSTS, rate limiting, Argon2/bcrypt, audit immutability, and real threat-intelligence adapters.

All demo identities, domains and infrastructure are fictional.

## AI service (now functional)
CyberLens includes a local FastAPI NLP service at `ai-service/main.py`. It analyzes email language and supplied evidence and returns a structured verdict, confidence, AI score, and explainable findings. The Node API calls it automatically and falls back to local Node NLP if the Python service is unavailable.

Run in a separate terminal:
```bash
cd ai-service
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Then start the backend and frontend as usual. The UI will show the AI model name and whether `local-ai` or `local-fallback` was used.
