# Corvid

AI-powered cybersecurity threat intelligence platform built for the DigitalOcean Hackathon.

Corvid accepts Indicators of Compromise (IOCs), enriches them with data from multiple external threat intel sources, and uses a Gradient AI agent with RAG to produce structured security analyses for SOC teams.

## Quick Start

### Option A: Docker Compose (recommended)

```bash
# Configure environment
cp .env.example .env

# Start Postgres, Redis, and API
docker compose up -d

# Run database migrations (required on first start)
docker compose exec api alembic revision --autogenerate -m "initial schema"
docker compose exec api alembic upgrade head

# Verify it's working
curl http://localhost:8000/health
```

### Option B: Local Development

```bash
# Configure environment
cp .env.example .env

# Create virtualenv and install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Start Postgres and Redis (via Docker or local install)
docker compose up -d postgres redis

# Run database migrations (required on first start)
alembic revision --autogenerate -m "initial schema"
alembic upgrade head

# Start the API server
uvicorn corvid.api.main:app --reload
```

## How It Works

```
IOC submitted  →  Normalized &   →  External APIs    →  AI agent reasons    →  Structured
via API/UI        deduplicated      enrich data         over all evidence      analysis
(IP, hash,        (type detected,   (AbuseIPDB, NVD,    (RAG over CVEs,        returned
 domain, URL)      validated)        URLhaus, etc.)       ATT&CK, advisories)   to caller
```

### Example

```bash
curl -X POST http://localhost:8000/api/v1/iocs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [{"type": "ip", "value": "203.0.113.42"}],
    "context": "Observed in outbound traffic from web server",
    "priority": "high"
  }'
```

Response includes severity score, confidence level, related CVEs, MITRE ATT&CK techniques, enrichment data from multiple sources, and recommended actions.

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  corvid-ui  │────>│  FastAPI Gateway │────>│  Worker (Norm +   │────>│  Gradient Agent     │
│  (React SPA) │     │  (ingest+query)  │     │  Enrichment)      │     │  (RAG + tools)      │
└─────────────┘     └─────────────────┘     └──────────────────┘     └─────────────────────┘
                            │                        │                         │
                            └────────────────────────┴─────────────────────────┘
                                                     │
                                        ┌────────────┴────────────┐
                                        │  PostgreSQL + Vector DB  │
                                        └─────────────────────────┘
```

| Service | Role | Tech |
|---------|------|------|
| **corvid-ui** | Investigation Board — graph-based threat analysis workspace | React 19, TypeScript, Cytoscape.js, Zustand, Tailwind v4 |
| **FastAPI Gateway** | REST API for IOC submission and retrieval | Python, FastAPI |
| **Worker** | IOC normalization + external API enrichment | Python, Redis-backed queue |
| **Gradient Agent** | AI reasoning with tool-calling and RAG | Python, Gradient ADK |

## IOC Types Supported

| Type | Format | Example |
|------|--------|---------|
| `ip` | IPv4 or IPv6 | `203.0.113.42` |
| `domain` | FQDN | `evil.example.com` |
| `url` | Full URL | `https://evil.example.com/payload` |
| `hash_md5` | 32 hex chars | `d41d8cd98f00b204e9800998ecf8427e` |
| `hash_sha1` | 40 hex chars | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `hash_sha256` | 64 hex chars | `e3b0c44298fc1c149afbf4c8996fb924...` |
| `email` | Email address | `attacker@evil.example.com` |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/iocs/` | Create or update an IOC |
| `GET` | `/api/v1/iocs/` | List IOCs (filterable by type, paginated) |
| `GET` | `/api/v1/iocs/{ioc_id}` | Get a specific IOC by ID |
| `DELETE` | `/api/v1/iocs/{ioc_id}` | Delete an IOC |
| `POST` | `/api/v1/iocs/{ioc_id}/enrich` | Trigger enrichment for an IOC |
| `POST` | `/api/v1/iocs/analyze` | Submit IOC(s) for full analysis |
| `GET` | `/api/v1/analyses/{analysis_id}` | Get analysis results |
| `GET` | `/health` | Health check |

## Frontend (Investigation Board)

The `corvid-ui/` directory contains a React-based graph investigation workspace that connects to the Corvid API. SOC analysts can submit IOCs, visualize relationships (IOC → CVE → MITRE technique), expand nodes interactively, and drill into detail panels.

```bash
cd corvid-ui

# Install dependencies
npm install

# Start dev server (proxies /api to localhost:8000)
npm run dev

# Run tests (91 unit/component tests)
npm test

# Type-check and production build
npm run build
```

Key technologies: React 19, TypeScript 5.9, Vite 7, Cytoscape.js (graph engine), Zustand (state), Tailwind CSS v4 (dark theme).

See [docs/UI_DESIGN.md](docs/UI_DESIGN.md) for the full design specification and implementation plan.

## Testing

### Backend

```bash
pytest                                    # All tests
pytest tests/api/ tests/db/ -v            # Phase 1 tests
pytest tests/worker/ -v                   # Phase 2 tests
pytest --cov=corvid --cov-report=term     # With coverage
```

### Frontend

```bash
cd corvid-ui
npm test                                  # All tests (vitest)
npx vitest --watch                        # Watch mode
npx vitest run --coverage                 # With coverage
```

## Project Structure

```
corvid/
├── api/                    # FastAPI application
│   ├── main.py             # App entrypoint
│   ├── routes/
│   │   ├── iocs.py         # IOC CRUD + enrichment endpoints
│   │   └── analyses.py     # Analysis retrieval endpoints
│   └── models/             # Pydantic request/response models
│       ├── ioc.py
│       └── analysis.py
├── worker/                 # Background task processing
│   ├── normalizer.py       # IOC normalization, validation, type detection
│   ├── enrichment.py       # Base enrichment provider interface
│   ├── orchestrator.py     # Concurrent multi-provider enrichment
│   ├── tasks.py            # Queue task definitions
│   └── providers/          # External TI API integrations
│       ├── abuseipdb.py
│       ├── urlhaus.py
│       └── nvd.py
├── agent/                  # Gradient agent configuration (Phase 3)
├── ingestion/              # Knowledge base data pipeline (Phase 3)
├── db/
│   ├── models.py           # SQLAlchemy ORM models
│   ├── session.py          # Async DB session factory
│   └── migrations/         # Alembic migrations
├── config.py               # Application configuration
├── tests/
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml

corvid-ui/                  # Frontend — Investigation Board
├── src/
│   ├── components/         # React components
│   │   ├── InvestigationBoard.tsx   # Main layout (canvas + panels)
│   │   ├── GraphCanvas.tsx          # Cytoscape wrapper
│   │   ├── IOCInputBar.tsx          # IOC submission form
│   │   ├── DetailPanel.tsx          # Node detail side panel
│   │   ├── CVECard.tsx              # CVE detail card
│   │   ├── MitreOverlay.tsx         # MITRE technique card
│   │   ├── EnrichmentCard.tsx       # Per-source enrichment card
│   │   ├── SeverityGauge.tsx        # Color-coded 0-10 gauge
│   │   ├── SeverityLegend.tsx       # Color scale reference
│   │   └── LoadingOverlay.tsx       # Loading spinner
│   ├── hooks/              # API hooks (useAnalysis, useIOC, useEnrichment)
│   ├── stores/             # Zustand stores (graphStore, filterStore)
│   ├── lib/                # Utilities (api client, graph transforms, styles)
│   ├── types/              # TypeScript types (API, graph, filters)
│   └── __tests__/          # Unit and component tests
├── package.json
├── vite.config.ts
├── vitest.config.ts
└── tsconfig.json
```

## External Integrations

| Source | Data Provided | IOC Types |
|--------|--------------|-----------|
| AbuseIPDB | IP reputation scores, abuse reports | IP |
| URLhaus (abuse.ch) | Malicious URL database | URL, domain, IP |
| NVD API | CVE details, CVSS scores | All (keyword search) |
| MITRE ATT&CK | Technique/tactic descriptions | Behavioral mapping |

## Infrastructure (DigitalOcean)

| Component | DO Service |
|-----------|-----------|
| FastAPI Gateway | App Platform |
| Worker | App Platform worker |
| PostgreSQL | Managed Database |
| Redis | Managed Redis |
| Agent tools | DO Functions |
| Gradient Agent + KB | Gradient API |

## License

See [LICENSE](LICENSE) for details.
