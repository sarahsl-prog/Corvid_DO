# Corvid - Architecture & Build Plan

## Project Overview

Corvid is a cybersecurity threat intelligence platform built for the DigitalOcean Hackathon. It ingests IOCs (Indicators of Compromise), enriches them using external threat intel sources, and uses a Gradient AI agent with RAG over security data to produce contextual analysis for SOC teams.

---

## Architecture Decisions & Brainstorm

### 1. Service Boundaries

The system breaks into **five logical services**:

| Service | Responsibility | Tech |
|---------|---------------|------|
| **IOC Ingest API** | Accept IOCs from clients, validate, enqueue | FastAPI (Python) |
| **Normalizer Worker** | Dedup, classify IOC type, basic tagging | Python, consumes from queue |
| **Enrichment Worker** | Call external TI APIs (VT, NVD, URLhaus, etc.) | Python, consumes from queue |
| **Gradient Agent** | RAG + tool-calling reasoning layer | Python (Gradient ADK) |
| **Analysis API** | Expose agent results to clients | FastAPI (Python) - can be same process as Ingest API |

**Simplification for hackathon**: Merge the Ingest API and Analysis API into a single FastAPI service. The Normalizer and Enrichment workers can also be a single worker process with two stages. This cuts you from 5 deployments to 3:

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

### 2. Queue Strategy

**For hackathon scope**: Consider starting with a **PostgreSQL-backed task queue** (e.g., `asyncio` + polling, or a lightweight lib like `arq` with Redis). This avoids standing up RabbitMQ as a separate service.

**For production**: RabbitMQ or NATS on a dedicated Droplet makes sense for fan-out (one IOC triggers multiple enrichment sources in parallel).

**Recommendation**: Use **Redis** (DO Managed Redis) as both your queue backend and cache layer. It's one managed service that handles:
- Task queue (via `arq` or `celery`)
- Caching enrichment results (TI API lookups are slow and rate-limited)
- Rate limiting external API calls

### 3. Data Store Design

#### PostgreSQL (DO Managed Database)

Core tables:

```
iocs
├── id (uuid)
├── type (enum: ip, domain, hash_md5, hash_sha1, hash_sha256, url, email)
├── value (text, indexed)
├── first_seen (timestamp)
├── last_seen (timestamp)
├── tags (jsonb)
├── severity_score (float, 0-10)
└── created_at / updated_at

enrichments
├── id (uuid)
├── ioc_id (fk -> iocs)
├── source (enum: virustotal, nvd, urlhaus, abuseipdb, shodan, ...)
├── raw_response (jsonb)
├── summary (text)
├── fetched_at (timestamp)
└── ttl_expires_at (timestamp)

analyses
├── id (uuid)
├── ioc_ids (uuid[])
├── agent_trace_id (text)
├── analysis_text (text)
├── confidence (float)
├── mitre_techniques (text[])
├── recommended_actions (jsonb)
├── created_at (timestamp)
└── model_version (text)

cve_references
├── id (uuid)
├── cve_id (text, e.g. "CVE-2024-1234")
├── ioc_id (fk -> iocs, nullable)
├── analysis_id (fk -> analyses, nullable)
├── cvss_score (float)
└── description (text)
```

#### Vector Store (Gradient Knowledge Base / OpenSearch)

Store embeddings of:
- NVD CVE descriptions + metadata
- Vendor security advisories
- MITRE ATT&CK technique descriptions
- Past Corvid analyses (for "have we seen similar IOCs?" retrieval)

### 4. Gradient Agent Design

#### Tools to register with the agent:

```python
# Tool definitions for the Gradient agent
tools = [
    {
        "name": "lookup_ioc",
        "description": "Look up an IOC in the Corvid database. Returns enrichment data, past analyses, severity score, and tags.",
        "parameters": {"ioc_type": "string", "ioc_value": "string"}
    },
    {
        "name": "search_cves",
        "description": "Search for CVEs related to a software name, version, or keyword.",
        "parameters": {"query": "string", "max_results": "integer"}
    },
    {
        "name": "enrich_ioc_external",
        "description": "Fetch fresh threat intel from external sources (VirusTotal, AbuseIPDB, URLhaus) for an IOC.",
        "parameters": {"ioc_type": "string", "ioc_value": "string", "sources": "string[]"}
    },
    {
        "name": "search_knowledge_base",
        "description": "Semantic search over CVE advisories, threat reports, and MITRE ATT&CK descriptions.",
        "parameters": {"query": "string", "top_k": "integer"}
    },
    {
        "name": "get_related_iocs",
        "description": "Find IOCs that have appeared together in past analyses or share infrastructure.",
        "parameters": {"ioc_type": "string", "ioc_value": "string"}
    }
]
```

#### Agent system prompt (sketch):

> You are Corvid, a cybersecurity threat intelligence analyst. Given an IOC, use your tools to gather all available intelligence, then produce a structured analysis covering: (1) what is known about this IOC, (2) severity assessment with confidence level, (3) related CVEs and MITRE ATT&CK techniques, (4) recommended mitigations, (5) related IOCs or campaigns. Always cite your sources. If data is limited, say so clearly rather than speculating.

#### Guardrails to implement:
- **Input sanitization**: IOC values could contain injection attempts. Validate IOC format strictly before passing to agent.
- **Output validation**: Parse agent output as structured JSON; reject/retry if it doesn't match schema.
- **Rate limiting**: Cap agent invocations per client to prevent abuse.
- **Audit logging**: Log every agent trace (input, tool calls, output) for review.

### 5. Knowledge Base Ingestion Pipeline

Sources to ingest into the RAG knowledge base:

| Source | Format | Update Frequency | Notes |
|--------|--------|-----------------|-------|
| NVD CVE Feed | JSON | Daily | ~250k CVEs, chunk by CVE |
| MITRE ATT&CK | STIX 2.1 JSON | Quarterly | Techniques, tactics, groups |
| CISA KEV | JSON | As published | Known exploited vulns |
| Vendor advisories | HTML/JSON | Varies | Microsoft, Cisco, etc. |
| URLhaus | CSV/API | Hourly | Malicious URLs |
| Abuse.ch ThreatFox | JSON/API | Real-time | IOC database |

**Chunking strategy**: Each CVE, advisory, or technique becomes one document. Include structured metadata (CVSS score, affected products, publish date) alongside the text for hybrid search.

### 6. API Design

#### POST /api/v1/iocs/analyze

```json
// Request
{
  "iocs": [
    {"type": "ip", "value": "203.0.113.42"},
    {"type": "hash_sha256", "value": "a1b2c3..."}
  ],
  "context": "Observed in outbound traffic from web server",
  "priority": "high"
}

// Response
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

#### GET /api/v1/iocs/{ioc_value}
Return stored data + past analyses for an IOC.

#### GET /api/v1/analyses/{analysis_id}
Return a specific analysis by ID.

### 7. DigitalOcean Infrastructure

| Component | DO Service | Sizing (hackathon) |
|-----------|-----------|-------------------|
| FastAPI Gateway | App Platform (or 1 Droplet) | Basic tier |
| Worker | App Platform worker (or same Droplet) | Basic tier |
| PostgreSQL | Managed Database | 1 GB RAM plan |
| Redis | Managed Redis | 1 GB plan |
| Agent tools | DO Functions | Pay-per-invocation |
| Gradient Agent | Gradient API | API calls |
| Knowledge Base | Gradient KB (managed) | - |
| Container Registry | DO Container Registry | Free tier |

### 8. Suggested Directory Structure

```
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

corvid-ui/                  # Frontend — Investigation Board
├── src/
│   ├── components/         # React components (GraphCanvas, DetailPanel, etc.)
│   ├── hooks/              # API hooks (useAnalysis, useIOC, useEnrichment)
│   ├── stores/             # Zustand stores (graphStore, filterStore)
│   ├── lib/                # Utilities (api client, graph transforms, styles)
│   ├── types/              # TypeScript types mirroring Pydantic models
│   └── __tests__/          # Unit and component tests (Vitest + RTL)
├── package.json
├── vite.config.ts
└── tsconfig.json
```

---

## Build Plan (Phased)

### Phase 1: Foundation (Day 1)
- [ ] Set up Python project (pyproject.toml, FastAPI skeleton)
- [ ] Define Pydantic models for IOC types and API request/response
- [ ] Set up PostgreSQL schema + SQLAlchemy models + Alembic
- [ ] Implement basic IOC CRUD endpoints
- [ ] Docker Compose for local dev (Postgres + Redis + API)

### Phase 2: Enrichment Pipeline (Day 2)
- [ ] Implement IOC normalizer (type detection, validation, dedup)
- [ ] Build enrichment integrations (start with 2-3 free APIs):
  - AbuseIPDB (IP reputation)
  - URLhaus (malicious URL lookup)
  - NVD API (CVE search)
- [ ] Wire up Redis task queue (arq or celery)
- [ ] Test end-to-end: submit IOC → normalize → enrich → store

### Phase 3: Gradient Agent + RAG (Day 3)
- [ ] Ingest NVD CVE data + MITRE ATT&CK into Gradient Knowledge Base
- [ ] Implement agent tools as DO Functions (or local HTTP endpoints)
- [ ] Configure Gradient agent with system prompt + tools + KB
- [ ] Build the /analyze endpoint that invokes the agent
- [ ] Add guardrails (input validation, output schema enforcement)

### Phase UI: Investigation Board Frontend (Implemented)
- [x] Scaffold Vite + React 19 + TypeScript + Tailwind v4 project (`corvid-ui/`)
- [x] Cytoscape.js graph engine with dagre/cose-bilkent layouts
- [x] IOC submission form with auto-type detection (mirrors backend `_IOC_PATTERNS`)
- [x] API integration hooks (`useAnalysis`, `useIOC`, `useEnrichment`)
- [x] Graph transforms: `AnalyzeResponse` → Cytoscape nodes/edges
- [x] Detail panel with CVECard, MitreOverlay, EnrichmentCard, SeverityGauge
- [x] "Expand & Enrich" interactive graph exploration
- [x] 91 unit/component tests (Vitest + RTL)

### Phase 4: Polish & Deploy (Day 4)
- [ ] Deploy to DigitalOcean (App Platform or Droplets)
- [x] Add a web UI (see Phase UI above)
- [ ] Write up documentation
- [ ] Load test and harden
- [ ] Record demo

---

## Key Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| External TI API rate limits | Enrichment bottleneck | Cache aggressively in Redis; respect rate limits with backoff |
| Agent hallucinating CVEs | Wrong threat intel = dangerous | Validate CVE IDs against NVD; require tool-sourced citations |
| RAG retrieval quality | Irrelevant context → bad analysis | Test chunking strategy; use hybrid search (keyword + semantic) |
| Gradient ADK learning curve | Dev time | Start with simplest agent config; iterate |
| Scope creep | Won't finish | Hackathon MVP = one IOC type (IP) end-to-end, then expand |

---

## MVP Scope (Hackathon Minimum)

If time is tight, the **minimum viable demo** is:

1. FastAPI endpoint accepts an IP address
2. Enrichment from 1-2 free APIs (AbuseIPDB + NVD)
3. Gradient agent with RAG over a small CVE subset
4. Returns structured JSON analysis
5. Simple web form or curl demo

Everything else (multiple IOC types, queue, full knowledge base, UI) is stretch.
