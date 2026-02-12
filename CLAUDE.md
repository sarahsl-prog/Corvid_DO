# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Corvid is a cybersecurity threat intelligence platform built for the DigitalOcean Hackathon. It ingests IOCs (Indicators of Compromise), enriches them using external threat intel sources, and uses a Gradient AI agent with RAG over security data to produce contextual analysis for SOC teams.

Agent system prompt (sketch):
You are Corvid, a cybersecurity threat intelligence analyst. Given an IOC, use your tools to gather all available intelligence, then produce a structured analysis covering: (1) what is known about this IOC, (2) severity assessment with confidence level, (3) related CVEs and MITRE ATT&CK techniques, (4) recommended mitigations, (5) related IOCs or campaigns. Always cite your sources. If data is limited, say so clearly rather than speculating.

# Code 
 - modular code
 - well commented
 - type-checking
 - use loguru for logging on all major features
 - vigorous error checking on all user input
 - create pytest test for features as they are implemented 

## Build and Run Commands

### Backend
```bash
# Setup
cp .env.example .env          # Configure environment
uv venv && source .venv/bin/activate
uv pip install -r requirements-dev.txt
pre-commit install
```

### Frontend (corvid-ui)
```bash
cd corvid-ui
npm install                   # Install dependencies
npm run dev                   # Dev server (proxies /api to localhost:8000)
npm run build                 # Type-check + production build
```

## Testing

### Backend
```bash
pytest                                    # All tests
pytest -m phase1                          # Phase 1 tests only
pytest tests/unit/test_ollama_client.py  # Single test file
pytest --cov=assistant --cov-report=html  # With coverage
```

Test structure: `tests/unit/`, `tests/integration/`, `tests/e2e/`, with shared fixtures in `tests/conftest.py`.

### Frontend
```bash
cd corvid-ui
npm test                                  # All tests (vitest)
npx vitest --watch                        # Watch mode
npx vitest run --coverage                 # With coverage
```

Test structure: `corvid-ui/src/__tests__/` with subdirectories `components/`, `stores/`, `lib/`.

## Code Quality

```bash
pre-commit run --all-files    # All checks (ruff, black, mypy, bandit)
ruff check --fix .            # Lint and fix
black .                       # Format
mypy assistant/               # Type check
```

Configuration in `pyproject.toml` (100 char line length).

## Architecture

1. Service Boundaries
The system breaks into five logical services:

Service	Responsibility										--								        Tech

IOC Ingest API	Accept IOCs from clients, validate, enqueue	--		FastAPI (Python)

Normalizer Worker	Dedup, classify IOC type, basic tagging	--		Python, consumes from queue

Enrichment Worker	Call external TI APIs (VT, NVD, URLhaus, etc.)	-- Python, consumes from queue

Gradient Agent	RAG + tool-calling reasoning layer		--				Python (Gradient ADK)

Analysis API	Expose agent results to clients			--						FastAPI (Python) - can be same process as Ingest API

##Directory Structure
```bash

corvid/
├── api/                    # FastAPI application
│   ├── main.py            # App entrypoint
│   ├── routes/
│   │   ├── iocs.py        # IOC endpoints
│   │   └── analyses.py    # Analysis endpoints
│   ├── models/            # Pydantic models
│   │   ├── ioc.py
│   │   └── analysis.py
│   └── dependencies.py    # DB sessions, auth, etc.
├── agent/                  # Gradient agent configuration
│   ├── agent.py           # Agent setup & system prompt
│   ├── tools/             # Tool implementations
│   │   ├── lookup_ioc.py
│   │   ├── search_cves.py
│   │   ├── enrich_external.py
│   │   └── search_kb.py
│   └── guardrails.py      # Input/output validation
├── worker/                 # Background task processing
│   ├── tasks.py           # Task definitions
│   ├── normalizer.py      # IOC normalization logic
│   └── enrichment.py      # External API enrichment
├── ingestion/              # Knowledge base data pipeline
│   ├── nvd.py             # NVD CVE ingestion
│   ├── mitre.py           # MITRE ATT&CK ingestion
│   └── advisories.py      # Vendor advisory ingestion
├── db/                     # Database
│   ├── models.py          # SQLAlchemy models
│   ├── migrations/        # Alembic migrations
│   └── session.py         # DB session factory
├── functions/              # DO Functions (agent tools)
│   ├── lookup_ioc/
│   ├── fetch_cves/
│   └── enrich_ti/
├── tests/
├── docker-compose.yml      # Local dev environment
├── Dockerfile
├── pyproject.toml
└── README.md

corvid-ui/                  # Frontend — Investigation Board (React 19 + Cytoscape.js)
├── src/
│   ├── components/         # React components (GraphCanvas, DetailPanel, IOCInputBar, etc.)
│   ├── hooks/              # API hooks (useAnalysis, useIOC, useEnrichment)
│   ├── stores/             # Zustand stores (graphStore, filterStore)
│   ├── lib/                # Utilities (api client, graph transforms, Cytoscape styles)
│   ├── types/              # TypeScript types mirroring Pydantic models
│   └── __tests__/          # Unit and component tests (Vitest + RTL)
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## API Endpoints

POST /api/v1/iocs/analyze
// Request
```python
{
  "iocs": [
    {"type": "ip", "value": "203.0.113.42"},
    {"type": "hash_sha256", "value": "a1b2c3..."}
  ],
  "context": "Observed in outbound traffic from web server",
  "priority": "high"
}
```
// Response
```python
{
  "analysis_id": "uuid",
  "status": "completed",
  "results": [
    {
      "ioc": {"type": "ip", "value": "203.0.113.42"},
      "severity": 7.8,
      "confidence": 0.85,
      "summary": "This IP is associated with...",
      "related_cves": ["CVE-2024-..."],
      "mitre_techniques": ["T1071.001"],
      "enrichments": {...},
      "recommended_actions": [...]
    }
  ]
}
```
GET /api/v1/iocs/{ioc_value}
Return stored data + past analyses for an IOC.

GET /api/v1/analyses/{analysis_id}
Return a specific analysis by ID.








