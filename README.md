# Corvid

AI-powered cybersecurity threat intelligence platform built for the DigitalOcean Hackathon.

Corvid accepts Indicators of Compromise (IOCs), enriches them with data from multiple external threat intel sources, and uses a Gradient AI agent with RAG to produce structured security analyses for SOC teams.

## Quick Start

```bash
# Clone and configure
cp .env.example .env

# Option A: Docker Compose (recommended)
docker compose up -d

# Option B: Local development
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
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
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  FastAPI Gateway │────>│  Worker (Norm +   │────>│  Gradient Agent     │
│  (ingest+query)  │     │  Enrichment)      │     │  (RAG + tools)      │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
        │                        │                         │
        └────────────────────────┴─────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  PostgreSQL + Vector DB  │
                    └─────────────────────────┘
```

| Service | Role | Tech |
|---------|------|------|
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

## Testing

```bash
pytest                                    # All tests
pytest tests/api/ tests/db/ -v            # Phase 1 tests
pytest tests/worker/ -v                   # Phase 2 tests
pytest --cov=corvid --cov-report=term     # With coverage
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
