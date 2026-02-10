# Corvid - Cybersecurity Threat Intelligence Platform

## What is Corvid?

Corvid is an AI-powered threat intelligence platform that accepts Indicators of Compromise (IOCs), enriches them with data from multiple external sources, and uses a Gradient AI agent with retrieval-augmented generation (RAG) to produce structured, contextual security analyses for SOC (Security Operations Center) teams.

Built for the DigitalOcean Hackathon, Corvid runs entirely on DigitalOcean infrastructure using Gradient for AI capabilities.

## Problem Statement

Security analysts face an overwhelming volume of IOCs daily. For each one, they must manually:
- Search multiple threat intel databases
- Cross-reference CVEs and vendor advisories
- Map activity to MITRE ATT&CK techniques
- Assess severity and prioritize response
- Write up findings for their team

Corvid automates this workflow end-to-end.

## How It Works

```
  IOC submitted        Normalized &          External APIs          AI agent reasons
  via API/UI     →     deduplicated    →     enrich data      →    over all evidence    →   Structured analysis
  (IP, hash,           (type detected,       (AbuseIPDB, NVD,      (RAG over CVEs,          returned to caller
   domain, URL)         validated)            URLhaus, etc.)         ATT&CK, advisories)
```

### Request/Response Example

**Submit an IOC for analysis:**

```bash
curl -X POST https://corvid.example.com/api/v1/iocs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [{"type": "ip", "value": "203.0.113.42"}],
    "context": "Observed in outbound traffic from web server",
    "priority": "high"
  }'
```

**Receive structured analysis:**

```json
{
  "analysis_id": "a1b2c3d4-...",
  "status": "completed",
  "results": [
    {
      "ioc": {"type": "ip", "value": "203.0.113.42"},
      "severity": 7.8,
      "confidence": 0.85,
      "summary": "This IP is associated with known C2 infrastructure...",
      "related_cves": ["CVE-2024-21762"],
      "mitre_techniques": ["T1071.001", "T1105"],
      "enrichments": {
        "abuseipdb": {"abuse_confidence_score": 92, "total_reports": 47},
        "urlhaus": {"urls_hosted": 3, "threat": "malware_download"}
      },
      "recommended_actions": [
        "Block IP at perimeter firewall",
        "Search proxy logs for connections to this IP in last 30 days",
        "Check affected hosts for indicators of T1105 (Ingress Tool Transfer)"
      ]
    }
  ]
}
```

## Architecture Overview

Corvid is composed of three deployed services backed by managed data stores:

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

### Services

| Service | Role | Technology |
|---------|------|-----------|
| **FastAPI Gateway** | REST API for IOC submission and analysis retrieval | Python, FastAPI |
| **Worker** | Normalizes IOCs and runs enrichment against external APIs | Python, arq (Redis-backed queue) |
| **Gradient Agent** | AI reasoning layer with tool-calling and RAG | Python, Gradient ADK |

### Data Stores

| Store | Purpose | Service |
|-------|---------|---------|
| **PostgreSQL** | IOC records, enrichment results, analyses, audit logs | DO Managed Database |
| **Redis** | Task queue, enrichment cache, rate limiting | DO Managed Redis |
| **Gradient Knowledge Base** | Embeddings of CVEs, advisories, ATT&CK techniques for RAG | Gradient managed |

### External Integrations

| Source | Data Provided | IOC Types |
|--------|--------------|-----------|
| AbuseIPDB | IP reputation scores, abuse reports | IP addresses |
| URLhaus (abuse.ch) | Malicious URL database | URLs, domains |
| NVD API | CVE details, CVSS scores, affected products | Software/version context |
| MITRE ATT&CK | Technique/tactic/group descriptions | Behavioral mapping |
| CISA KEV | Known exploited vulnerabilities | CVE cross-reference |

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
| `POST` | `/api/v1/iocs/analyze` | Submit IOC(s) for analysis |
| `GET` | `/api/v1/iocs/{ioc_value}` | Retrieve stored data and past analyses for an IOC |
| `GET` | `/api/v1/analyses/{analysis_id}` | Retrieve a specific analysis by ID |
| `GET` | `/health` | Service health check |

## Database Schema

### `iocs` table
Stores each unique IOC with its type, first/last seen timestamps, severity score, and tags.

### `enrichments` table
Stores raw and summarized results from each external TI source, linked to an IOC. Includes TTL for cache invalidation.

### `analyses` table
Stores the Gradient agent's structured output including analysis text, confidence score, MITRE technique mappings, and recommended actions.

### `cve_references` table
Links CVE IDs (with CVSS scores and descriptions) to IOCs and analyses.

## Security Considerations

- **Input validation**: All IOC values are validated against strict format patterns before processing. No raw IOC strings are passed to the agent without sanitization.
- **Output validation**: Agent responses are parsed against a JSON schema. Malformed responses trigger a retry or error.
- **Rate limiting**: API endpoints and agent invocations are rate-limited per client.
- **Audit logging**: Every agent trace (input, tool calls, output) is logged for review and debugging.
- **RAG poisoning defense**: Knowledge base ingestion only accepts data from trusted, verified sources.
- **No secret exposure**: API keys for external services are stored as environment variables, never in code or logs.

## Project Structure

```
corvid/
├── api/                    # FastAPI application
│   ├── main.py
│   ├── routes/
│   │   ├── iocs.py
│   │   └── analyses.py
│   ├── models/
│   │   ├── ioc.py
│   │   └── analysis.py
│   └── dependencies.py
├── agent/                  # Gradient agent configuration
│   ├── agent.py
│   ├── tools/
│   │   ├── lookup_ioc.py
│   │   ├── search_cves.py
│   │   ├── enrich_external.py
│   │   └── search_kb.py
│   └── guardrails.py
├── worker/                 # Background task processing
│   ├── tasks.py
│   ├── normalizer.py
│   └── enrichment.py
├── ingestion/              # Knowledge base data pipeline
│   ├── nvd.py
│   ├── mitre.py
│   └── advisories.py
├── db/
│   ├── models.py
│   ├── migrations/
│   └── session.py
├── functions/              # DO Functions (agent tools)
├── tests/
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Infrastructure (DigitalOcean)

| Component | DO Service | Hackathon Sizing |
|-----------|-----------|-----------------|
| FastAPI Gateway | App Platform | Basic tier |
| Worker | App Platform worker | Basic tier |
| PostgreSQL | Managed Database | 1 GB RAM |
| Redis | Managed Redis | 1 GB |
| Agent tools | DO Functions | Pay-per-invocation |
| Gradient Agent | Gradient API | API calls |
| Knowledge Base | Gradient KB | Managed |
| Container Registry | DO Container Registry | Free tier |
