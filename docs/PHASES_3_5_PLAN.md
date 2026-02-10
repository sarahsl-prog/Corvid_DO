# Phases 3-5: Implementation Plan

**Prerequisite**: Phase 1 (foundation) and Phase 2 (enrichment pipeline) are complete with 109 passing tests.

---

## Phase 3: Gradient Agent + RAG

**Goal**: Integrate the Gradient AI agent with tool-calling and retrieval-augmented generation (RAG) over security data, build the knowledge base ingestion pipeline, and expose the full `/analyze` endpoint.

---

### Step 1: Knowledge Base Ingestion Pipeline

Build scripts that fetch, chunk, and prepare security data for the Gradient knowledge base.

#### 1.1 `corvid/ingestion/nvd.py` — NVD CVE Ingestion

Fetches CVEs from the NVD 2.0 API and chunks them into individual documents for the knowledge base.

```python
# Core logic:
# - Paginate through NVD API (2,000 results per page)
# - For each CVE, extract: ID, description (EN), CVSS score, affected products,
#   published date, references
# - Format as a structured document with metadata
# - Output: list of dicts ready for KB upload

@dataclass
class CVEDocument:
    cve_id: str              # "CVE-2024-21762"
    description: str         # English description text
    cvss_score: float | None # Base score
    severity: str            # "CRITICAL", "HIGH", etc.
    affected_products: list[str]
    published: str           # ISO date
    references: list[str]    # Reference URLs
    content: str             # Full text for embedding (formatted from above fields)
```

**Chunking strategy**: One document per CVE. The `content` field combines all fields into a single searchable text block.

**Scope for hackathon**: Ingest only recent CVEs (last 2 years, ~20k) rather than the full 250k+ database.

#### 1.2 `corvid/ingestion/mitre.py` — MITRE ATT&CK Ingestion

Fetches MITRE ATT&CK data from the official STIX 2.1 JSON bundle.

```python
# Core logic:
# - Download ATT&CK Enterprise STIX bundle from GitHub
# - Parse attack-pattern objects (techniques)
# - Extract: technique ID, name, description, tactics, platforms,
#   data sources, mitigations
# - Format as documents for KB

@dataclass
class MITREDocument:
    technique_id: str        # "T1071.001"
    name: str                # "Application Layer Protocol: Web Protocols"
    description: str
    tactics: list[str]       # ["command-and-control"]
    platforms: list[str]     # ["Windows", "Linux", "macOS"]
    data_sources: list[str]
    mitigations: list[str]
    content: str             # Full text for embedding
```

**Scope**: All Enterprise ATT&CK techniques (~700 documents). Small enough to ingest entirely.

#### 1.3 `corvid/ingestion/advisories.py` — CISA KEV Ingestion

Fetches the CISA Known Exploited Vulnerabilities catalog.

```python
# Core logic:
# - GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# - Parse each vulnerability entry
# - Cross-reference with NVD data where available
# - Format as documents
```

**Scope**: ~1,200 KEV entries. Small, high-value dataset for "is this CVE actively exploited?"

#### 1.4 `corvid/ingestion/loader.py` — Knowledge Base Upload Coordinator

Orchestrates ingestion from all sources and uploads to the Gradient knowledge base.

```python
async def build_knowledge_base():
    """Fetch all sources, deduplicate, and upload to Gradient KB."""
    cve_docs = await fetch_nvd_cves(years=2)
    mitre_docs = await fetch_mitre_attack()
    kev_docs = await fetch_cisa_kev()

    all_docs = cve_docs + mitre_docs + kev_docs
    logger.info("Total documents for KB: {}", len(all_docs))

    # Upload to Gradient KB via API
    await upload_to_gradient_kb(all_docs)
```

#### Tests: `tests/ingestion/test_ingestion.py`

```
- test_nvd_document_parsing (mock NVD API response → verify CVEDocument fields)
- test_nvd_pagination (mock multi-page response → verify all pages fetched)
- test_nvd_handles_missing_fields (CVE with no CVSS → None, no desc → empty)
- test_mitre_technique_parsing (mock STIX bundle → verify MITREDocument)
- test_mitre_filters_enterprise_only (skip non-enterprise objects)
- test_kev_parsing (mock KEV JSON → verify documents)
- test_loader_deduplicates (same CVE from NVD + KEV → one document)
- test_loader_combines_all_sources (verify total count)
```

---

### Step 2: Agent Tool Implementations

Each tool the Gradient agent can call is a Python function that queries local data or external APIs.

#### 2.1 `corvid/agent/tools/lookup_ioc.py`

```python
async def lookup_ioc(ioc_type: str, ioc_value: str) -> dict:
    """Look up an IOC in the Corvid database.

    Returns enrichment data, past analyses, severity score, and tags.
    Called by the Gradient agent during analysis.
    """
    # Query DB for IOC by type+value
    # Include: enrichments (all sources), tags, severity_score,
    #          first_seen, last_seen, past analysis summaries
    # Return structured dict the agent can reason over
```

#### 2.2 `corvid/agent/tools/search_cves.py`

```python
async def search_cves(query: str, max_results: int = 5) -> dict:
    """Search for CVEs related to a keyword.

    Queries both the local cve_references table and the NVD API.
    Returns CVE IDs, descriptions, and CVSS scores.
    """
```

#### 2.3 `corvid/agent/tools/enrich_external.py`

```python
async def enrich_ioc_external(
    ioc_type: str, ioc_value: str, sources: list[str] | None = None
) -> dict:
    """Fetch fresh threat intel from external sources.

    Wraps the existing enrichment orchestrator so the agent can trigger
    on-demand enrichment during analysis.
    """
```

#### 2.4 `corvid/agent/tools/search_kb.py`

```python
async def search_knowledge_base(query: str, top_k: int = 5) -> dict:
    """Semantic search over the Gradient knowledge base.

    Searches CVE advisories, MITRE ATT&CK techniques, and CISA KEV entries.
    Returns the top-k most relevant documents.
    """
    # Call Gradient KB search API
    # Return: list of {title, content_snippet, metadata, relevance_score}
```

#### Tests: `tests/agent/test_tools.py`

```
- test_lookup_ioc_found (IOC exists in DB → returns enrichments + tags)
- test_lookup_ioc_not_found (IOC not in DB → empty result with message)
- test_search_cves_with_results (mock NVD → returns CVE list)
- test_search_cves_empty (no matches → empty list)
- test_enrich_external_delegates_to_orchestrator (verify orchestrator called)
- test_search_kb_returns_documents (mock Gradient KB API → documents)
- test_search_kb_empty (no matches → empty list with message)
```

---

### Step 3: Gradient Agent Configuration

#### 3.1 `corvid/agent/agent.py` — Agent Setup

```python
# Core responsibilities:
# - Initialize Gradient agent client
# - Register system prompt
# - Register all tools with schemas
# - Handle agent invocation (send IOC context, receive analysis)
# - Parse and validate structured output

SYSTEM_PROMPT = """You are Corvid, a cybersecurity threat intelligence analyst.
Given an IOC (Indicator of Compromise), use your tools to gather all available
intelligence, then produce a structured analysis.

Your analysis MUST include:
1. **Summary**: What is known about this IOC (2-3 sentences)
2. **Severity**: Score from 0.0-10.0 with justification
3. **Confidence**: Your confidence level (0.0-1.0) in the assessment
4. **Related CVEs**: List any CVE IDs found, with brief descriptions
5. **MITRE ATT&CK**: Map to relevant technique IDs with names
6. **Enrichments**: Key findings from each source consulted
7. **Recommended Actions**: Specific, actionable steps for the SOC team
8. **Related IOCs**: Any associated indicators discovered

Always cite which tool/source provided each piece of data.
If data is limited, say so clearly rather than speculating.
Respond ONLY with valid JSON matching the required schema."""

class CorvidAgent:
    def __init__(self, gradient_api_key: str, kb_id: str):
        # Initialize Gradient client
        # Register tools
        pass

    async def analyze_ioc(
        self, ioc_type: str, ioc_value: str, context: str = ""
    ) -> AnalysisResult:
        # 1. Build user message with IOC details and optional context
        # 2. Invoke agent (tool-calling loop)
        # 3. Parse structured JSON output
        # 4. Validate against AnalysisResult schema
        # 5. Return result
        pass
```

#### 3.2 `corvid/agent/guardrails.py` — Input/Output Validation

```python
# Input guardrails:
# - Validate IOC format before passing to agent
# - Strip/escape any potential injection in context field
# - Enforce max context length

# Output guardrails:
# - Parse agent response as JSON
# - Validate against AnalysisResult Pydantic model
# - Verify CVE IDs match CVE-YYYY-NNNNN format
# - Verify MITRE technique IDs match T####.### format
# - If validation fails, retry once with error feedback
# - Log full agent trace for audit
```

#### Tests: `tests/agent/test_agent.py`

```
- test_agent_initialization (verify tools registered)
- test_analyze_ioc_returns_structured_result (mock Gradient API → valid analysis)
- test_analyze_ioc_with_context (context passed to agent prompt)
- test_analyze_ioc_handles_agent_error (Gradient API error → graceful failure)
- test_input_guardrails_valid_ioc (valid IP passes)
- test_input_guardrails_rejects_injection (SQL/prompt injection blocked)
- test_output_guardrails_valid_json (good response passes validation)
- test_output_guardrails_invalid_json (bad response triggers retry)
- test_output_guardrails_invalid_cve_format (fake CVE ID flagged)
- test_output_guardrails_invalid_mitre_format (fake technique ID flagged)
- test_audit_logging (verify trace logged)
```

---

### Step 4: The `/analyze` Endpoint

#### 4.1 Update `corvid/api/routes/analyses.py`

```python
@router.post("/analyze", status_code=200)
async def analyze_iocs(request: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Submit IOC(s) for full AI-powered analysis.

    Pipeline:
    1. Validate and normalize each IOC
    2. Create/update IOC records in DB
    3. Run enrichment on each IOC
    4. Invoke Gradient agent with IOC data + enrichments
    5. Store analysis in DB
    6. Return structured results
    """
```

#### 4.2 Pydantic models: `corvid/api/models/analysis.py` (update)

```python
class AnalyzeRequest(BaseModel):
    iocs: list[IOCCreate]
    context: str = ""
    priority: str = "medium"  # low, medium, high

class AnalysisResultItem(BaseModel):
    ioc: IOCCreate
    severity: float
    confidence: float
    summary: str
    related_cves: list[str]
    mitre_techniques: list[str]
    enrichments: dict[str, Any]
    recommended_actions: list[str]

class AnalyzeResponse(BaseModel):
    analysis_id: UUID
    status: str  # "completed", "partial", "failed"
    results: list[AnalysisResultItem]
```

#### Tests: `tests/api/test_analyze.py`

```
- test_analyze_single_ip (mock agent → full response)
- test_analyze_multiple_iocs (2 IOCs → 2 results)
- test_analyze_with_context (context passed through to agent)
- test_analyze_invalid_ioc_rejected (bad type → 422)
- test_analyze_agent_failure_returns_partial (1 ok, 1 fails → partial)
- test_analyze_stores_analysis_in_db (verify DB record created)
- test_analyze_analysis_retrievable (POST analyze → GET analysis/{id})
```

---

### Phase 3 Test Summary

| Test File | Tests | Covers |
|-----------|-------|--------|
| `tests/ingestion/test_ingestion.py` | 8 | NVD, MITRE, KEV parsing + loader |
| `tests/agent/test_tools.py` | 7 | All 4 agent tools |
| `tests/agent/test_agent.py` | 11 | Agent init, analysis, guardrails |
| `tests/api/test_analyze.py` | 7 | /analyze endpoint integration |
| **Phase 3 subtotal** | **33** | |
| **Running total** | **142** | |

---

## Phase 4: Deploy to DigitalOcean

**Goal**: Deploy the full Corvid stack to DigitalOcean infrastructure and verify it works end-to-end in production.

---

### Step 1: Infrastructure Provisioning

#### 1.1 DigitalOcean Resources

| Resource | Service | Config |
|----------|---------|--------|
| PostgreSQL | Managed Database | `db-s-1vcpu-1gb`, `corvid` database |
| Redis | Managed Redis | `db-s-1vcpu-1gb` |
| App | App Platform | Web service from Dockerfile |
| Knowledge Base | Gradient KB | Created via Gradient API |

#### 1.2 `deploy/do-app-spec.yaml` — App Platform Specification

```yaml
name: corvid
services:
  - name: api
    dockerfile_path: Dockerfile
    github:
      repo: <your-repo>
      branch: main
    envs:
      - key: CORVID_DATABASE_URL
        scope: RUN_TIME
        type: SECRET
      - key: CORVID_REDIS_URL
        scope: RUN_TIME
        type: SECRET
      - key: GRADIENT_API_KEY
        scope: RUN_TIME
        type: SECRET
      - key: ABUSEIPDB_API_KEY
        scope: RUN_TIME
        type: SECRET
    http_port: 8000
    instance_count: 1
    instance_size_slug: basic-xxs
    routes:
      - path: /
```

#### 1.3 `deploy/provision.sh` — Infrastructure Setup Script

```bash
# Create managed Postgres
doctl databases create corvid-db --engine pg --size db-s-1vcpu-1gb --region nyc1

# Create managed Redis
doctl databases create corvid-redis --engine redis --size db-s-1vcpu-1gb --region nyc1

# Run Alembic migrations against production DB
alembic upgrade head

# Run knowledge base ingestion
python -m corvid.ingestion.loader

# Deploy via App Platform
doctl apps create --spec deploy/do-app-spec.yaml
```

### Step 2: Production Configuration

#### 2.1 `corvid/config.py` (update)

Add production settings:

```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Gradient AI
    gradient_api_key: str = ""
    gradient_kb_id: str = ""

    # External API keys
    abuseipdb_api_key: str = ""
    nvd_api_key: str = ""

    # Production tuning
    debug: bool = False
    log_level: str = "INFO"
    max_concurrent_enrichments: int = 5
    agent_timeout_seconds: int = 30
```

#### 2.2 Health Check Enhancements

```python
@app.get("/health")
async def health():
    """Deep health check: verify DB, Redis, and Gradient connectivity."""
    checks = {
        "db": await check_db_connection(),
        "redis": await check_redis_connection(),
        "gradient": await check_gradient_connection(),
    }
    status = "ok" if all(checks.values()) else "degraded"
    return {"status": status, "checks": checks}
```

### Step 3: Alembic Production Migration

#### 3.1 Generate and apply migration

```bash
# Generate migration from current models
alembic revision --autogenerate -m "initial production schema"

# Apply to production database
CORVID_DATABASE_URL=<production-url> alembic upgrade head
```

### Step 4: Smoke Tests

#### `tests/smoke/test_deployed.py`

Run against the deployed URL to verify the system works end-to-end:

```
- test_health_endpoint_ok (GET /health → 200)
- test_create_ioc (POST /api/v1/iocs/ → 201)
- test_list_iocs (GET /api/v1/iocs/ → 200 with items)
- test_enrich_ioc (POST /api/v1/iocs/{id}/enrich → 202)
- test_analyze_ioc (POST /api/v1/analyses/analyze → 200 with results)
- test_get_analysis (GET /api/v1/analyses/{id} → 200)
```

### Step 5: Logging & Monitoring

#### 5.1 Structured Logging

```python
# Configure loguru for production JSON output
logger.configure(
    handlers=[{
        "sink": sys.stdout,
        "format": "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
        "serialize": True,  # JSON format for DO log aggregation
    }]
)
```

#### 5.2 Key Metrics to Log

- IOC submission rate (per type)
- Enrichment latency per provider
- Agent analysis latency
- Error rates per provider
- Cache hit/miss ratio

---

### Phase 4 Test Summary

| Test File | Tests | Covers |
|-----------|-------|--------|
| `tests/smoke/test_deployed.py` | 6 | Production endpoint smoke tests |
| Updated `tests/api/test_iocs.py` | +2 | Enhanced health check tests |
| **Phase 4 subtotal** | **8** | |
| **Running total** | **150** | |

---

## Phase 5: Demo UI + Polish

**Goal**: Build a minimal web interface for the hackathon demo, add finishing touches, and record the demo.

---

### Step 1: Minimal Web UI

#### 1.1 `corvid/api/static/index.html` — Single-Page Demo

A lightweight single-page app served by FastAPI's `StaticFiles`. No build step, no framework — just vanilla HTML/CSS/JS.

```
Features:
- IOC input form (text field + type dropdown + optional context)
- "Analyze" button that calls POST /api/v1/analyses/analyze
- Loading spinner during analysis
- Results panel showing:
  - Severity gauge (color-coded 0-10)
  - Confidence badge
  - Summary text
  - Enrichment cards (one per provider)
  - CVE list (clickable links to NVD)
  - MITRE ATT&CK technique list (linkable to attack.mitre.org)
  - Recommended actions checklist
- Recent analyses sidebar (calls GET /api/v1/analyses/)
```

#### 1.2 Design Notes

- Dark theme (cybersecurity aesthetic, matches the Corvid branding)
- Responsive layout (works on laptop + projector for demo)
- No external CDN dependencies — everything self-contained
- Use CSS custom properties for the color palette

#### 1.3 Static File Serving

```python
# In corvid/api/main.py
from fastapi.staticfiles import StaticFiles

app.mount("/static", StaticFiles(directory="corvid/api/static"), name="static")

@app.get("/")
async def root():
    return FileResponse("corvid/api/static/index.html")
```

### Step 2: CLI Demo Tool

#### 2.1 `corvid/cli.py` — Command-Line Interface

A quick CLI for demo/testing without the UI:

```python
# Usage:
#   python -m corvid.cli analyze 203.0.113.42
#   python -m corvid.cli analyze --type domain evil.example.com
#   python -m corvid.cli analyze --type hash_sha256 <hash> --context "Found in phishing email"

# Features:
# - Rich terminal output (color-coded severity, formatted tables)
# - Auto-detects IOC type if not specified (uses normalizer)
# - Prints full analysis result in human-readable format
# - Optional --json flag for raw JSON output
```

### Step 3: Final Polish

#### 3.1 Error Handling Improvements

- Add global exception handler in FastAPI for clean error responses
- Add request ID middleware for correlating logs
- Ensure all error responses follow a consistent schema:
  ```json
  {"error": "message", "detail": "...", "request_id": "..."}
  ```

#### 3.2 Rate Limiting

```python
# Add slowapi rate limiting to protect the /analyze endpoint
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@router.post("/analyze")
@limiter.limit("10/minute")
async def analyze_iocs(...):
    ...
```

#### 3.3 CORS Configuration

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten for production
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### 3.4 OpenAPI Documentation Polish

- Add detailed descriptions to all endpoints
- Add example request/response bodies
- Tag endpoints by domain (IOCs, Analyses, Health)
- Ensure the auto-generated Swagger UI at `/docs` is presentation-ready

### Step 4: Demo Recording

#### 4.1 Demo Script (2-3 minutes)

```
1. Open Corvid web UI (10s)
   - Show the interface, explain what Corvid does

2. Submit a suspicious IP (20s)
   - Enter 203.0.113.42 with context "Found in firewall logs"
   - Click Analyze

3. Watch the analysis happen (30s)
   - Show loading state
   - Point out enrichment sources being queried
   - Results appear: severity 7.8, high confidence

4. Walk through results (60s)
   - Highlight severity score and confidence
   - Show CVE references (clickable to NVD)
   - Show MITRE ATT&CK mapping
   - Show recommended actions

5. Submit a malicious hash (30s)
   - Show it works across IOC types
   - Different enrichment sources activate

6. Show the API (20s)
   - Quick curl command to /analyze
   - Mention SIEM/SOAR integration potential

7. Architecture slide (10s)
   - Quick view of DO infrastructure
   - Mention Gradient agent + RAG
```

---

### Phase 5 Test Summary

| Test File | Tests | Covers |
|-----------|-------|--------|
| `tests/api/test_static.py` | 3 | Static file serving, root redirect |
| `tests/test_cli.py` | 4 | CLI analyze command, auto-detect, JSON output |
| `tests/api/test_middleware.py` | 3 | CORS, rate limiting, request ID |
| **Phase 5 subtotal** | **10** | |
| **Running total** | **160** | |

---

## Final Test Summary (All Phases)

| Phase | Test File | Tests |
|-------|-----------|-------|
| 1 | `tests/api/test_models.py` | 12 |
| 1 | `tests/db/test_models.py` | 9 |
| 1 | `tests/api/test_iocs.py` | 16 |
| 2 | `tests/worker/test_normalizer.py` | 30 |
| 2 | `tests/worker/test_enrichment.py` | 19 |
| 2 | `tests/worker/test_orchestrator.py` | 7 |
| 2 | `tests/worker/test_tasks.py` | 1 |
| 2 | `tests/test_e2e_pipeline.py` | 3 |
| 3 | `tests/ingestion/test_ingestion.py` | 8 |
| 3 | `tests/agent/test_tools.py` | 7 |
| 3 | `tests/agent/test_agent.py` | 11 |
| 3 | `tests/api/test_analyze.py` | 7 |
| 4 | `tests/smoke/test_deployed.py` | 6 |
| 4 | `tests/api/test_iocs.py` (updated) | +2 |
| 5 | `tests/api/test_static.py` | 3 |
| 5 | `tests/test_cli.py` | 4 |
| 5 | `tests/api/test_middleware.py` | 3 |
| | **TOTAL** | **~160** |

---

## Future Features (Post-Hackathon)

Ideas to implement after the core platform is fully tested and stable.

### High Priority

#### 1. STIX/TAXII Integration
- **What**: Accept and emit IOCs in STIX 2.1 format; support TAXII server polling for automated feed ingestion.
- **Why**: STIX/TAXII is the industry standard for threat intel sharing. This makes Corvid interoperable with existing SOC tooling (MISP, OpenCTI, ThreatConnect).
- **Effort**: Medium. Add a TAXII client for ingestion and a `/api/v1/iocs/stix` export endpoint.

#### 2. Webhook Notifications
- **What**: Allow users to register webhook URLs that receive POST notifications when high-severity IOCs are detected or when analysis is complete.
- **Why**: Enables integration with Slack, PagerDuty, SIEM alert channels, and SOAR playbooks without polling.
- **Effort**: Low. Add a `webhooks` table, a registration endpoint, and an async notification dispatcher.

#### 3. Bulk IOC Import
- **What**: Accept CSV, JSON, or STIX bundles containing hundreds or thousands of IOCs for batch processing.
- **Why**: SOC teams frequently export IOC lists from SIEMs. Manual one-by-one submission doesn't scale.
- **Effort**: Medium. Add a `POST /api/v1/iocs/bulk` endpoint with background processing and a status polling endpoint.

#### 4. IOC Correlation Engine
- **What**: Automatically identify relationships between IOCs (e.g., IPs that host the same malicious domains, hashes seen from the same C2 server).
- **Why**: Isolated IOC analysis misses the bigger picture. Correlation reveals campaigns and threat actor infrastructure.
- **Effort**: High. Requires a graph data model (or graph queries on Postgres) and correlation heuristics.

#### 5. Historical Trend Analysis
- **What**: Track IOC severity over time. Show graphs of how an IOC's reputation has changed (e.g., IP was clean last month, now flagged by 5 sources).
- **Why**: SOC analysts need temporal context. A newly malicious IP is more urgent than one that's been flagged for years.
- **Effort**: Medium. Requires timestamped enrichment snapshots and a charting endpoint.

### Medium Priority

#### 6. User Authentication & Multi-Tenancy
- **What**: Add API key authentication, user accounts, and organization-level data isolation.
- **Why**: Required for any production deployment beyond a single-team tool.
- **Effort**: Medium. Add JWT/API key auth middleware, a `users` table, and org-scoped queries.

#### 7. VirusTotal Integration
- **What**: Add VirusTotal as an enrichment provider for file hashes, URLs, and domains.
- **Why**: VT is the most widely used malware analysis platform. Its multi-engine scan results are a standard reference.
- **Effort**: Low. Follows the existing `BaseEnrichmentProvider` pattern. Requires a VT API key (free tier: 4 req/min).

#### 8. Shodan Integration
- **What**: Enrich IP IOCs with Shodan data (open ports, services, banners, known vulnerabilities).
- **Why**: Shodan reveals the attack surface of an IP -- what services are exposed and whether they're running vulnerable software.
- **Effort**: Low. Same provider pattern. Shodan API key required.

#### 9. Passive DNS Integration
- **What**: Add PassiveTotal, SecurityTrails, or similar for passive DNS lookups on domains and IPs.
- **Why**: Shows domain-to-IP history, revealing infrastructure changes and shared hosting patterns.
- **Effort**: Low. Same provider pattern.

#### 10. Caching Layer
- **What**: Cache enrichment results in Redis with configurable TTL per provider. Skip external API calls when fresh data exists.
- **Why**: External APIs are slow and rate-limited. Caching reduces latency from seconds to milliseconds for repeat lookups.
- **Effort**: Low. Add TTL-based cache checks in the orchestrator before calling providers.

### Lower Priority / Stretch

#### 11. Scheduled Feed Ingestion
- **What**: Cron-like scheduler that periodically pulls updated threat feeds (NVD, MITRE, URLhaus, ThreatFox) and refreshes the knowledge base.
- **Why**: The knowledge base goes stale without regular updates. CVEs are published daily.
- **Effort**: Medium. Add a scheduler (APScheduler or arq cron) and incremental update logic.

#### 12. Dashboard & Analytics
- **What**: A full dashboard showing IOC submission trends, top threat types, geographic distribution, severity distribution, and provider uptime.
- **Why**: SOC managers need visibility into what threats their team is investigating and how the platform is performing.
- **Effort**: High. Requires aggregation queries, a charting library, and a more complete frontend.

#### 13. Playbook Generation
- **What**: Extend the agent to generate SOAR-compatible playbooks (e.g., Cortex XSOAR, Splunk SOAR) based on the analysis.
- **Why**: Turns analysis into automated response. Instead of "block this IP", generate a playbook that does it across all firewalls.
- **Effort**: High. Requires understanding SOAR playbook formats and extending the agent's output schema.

#### 14. Confidence Calibration
- **What**: Track how accurate the agent's severity/confidence scores are over time by collecting analyst feedback ("was this assessment correct?").
- **Why**: Uncalibrated confidence is noise. Tracking accuracy lets you tune the agent and build trust with analysts.
- **Effort**: Medium. Add a feedback endpoint, a `feedback` table, and periodic accuracy reports.

#### 15. Multi-Model Support
- **What**: Allow switching between Gradient models (or other LLM providers) for the agent layer. Compare outputs across models.
- **Why**: Different models may excel at different analysis types. A/B testing improves quality over time.
- **Effort**: Medium. Abstract the agent client behind an interface; add model selection to the config.

---

## Implementation Priority Matrix

```
                        HIGH VALUE
                           ↑
    STIX/TAXII ·    · Correlation Engine
    Webhooks ·         · Playbook Gen
    Bulk Import ·   · Dashboard
    VT Integration ·  · Multi-Model
    Caching ·       · Confidence Cal
    Shodan ·        · Scheduled Feeds
    Passive DNS ·   · Auth/Multi-Tenant
                           ↓
                        LOW VALUE
    LOW EFFORT ←─────────────→ HIGH EFFORT
```

**Recommended order after hackathon**:
1. Caching Layer (quick win, big latency improvement)
2. VirusTotal + Shodan Integration (low effort, high value enrichment)
3. Webhooks (enables SOAR integration)
4. Bulk Import (enables real SOC workflows)
5. User Auth (required before any multi-team use)
6. STIX/TAXII (industry standard interop)
7. Everything else based on user feedback
