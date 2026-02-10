# Corvid Functional Testing Plan

Comprehensive testing plan for the Corvid threat intelligence platform covering all phases of implementation.

## Table of Contents

1. [Testing Overview](#testing-overview)
2. [Test Environments](#test-environments)
3. [Prerequisites](#prerequisites)
4. [Test Categories](#test-categories)
5. [Test Cases](#test-cases)
6. [Test Data](#test-data)
7. [Automated Test Scripts](#automated-test-scripts)
8. [Manual Testing Procedures](#manual-testing-procedures)
9. [Expected Results](#expected-results)
10. [Troubleshooting](#troubleshooting)

---

## Testing Overview

### Scope

| Phase | Component | Coverage |
|-------|-----------|----------|
| Phase 1 | Foundation | IOC CRUD, Database, API structure |
| Phase 2 | Enrichment | External APIs, Orchestration, Normalization |
| Phase 3 | Agent + RAG | Gradient AI, Knowledge Base, Analysis |
| Phase 4 | Deployment | Health checks, Logging, Production readiness |

### Test Types

- **Unit Tests**: Individual functions and classes (pytest)
- **Integration Tests**: Component interactions (pytest + fixtures)
- **API Tests**: HTTP endpoint validation (httpx/pytest)
- **Smoke Tests**: Deployed system verification
- **End-to-End Tests**: Full workflow validation
- **Performance Tests**: Response time and throughput

---

## Test Environments

### Local Development

```bash
# Start local infrastructure
docker-compose up -d

# Run migrations
uv run alembic upgrade head

# Start API server
uv run uvicorn corvid.api.main:app --reload --port 8000
```

**URLs:**
- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

### Staging/Production

```bash
# Set the deployed URL
export CORVID_TEST_URL="https://your-app.ondigitalocean.app"
```

---

## Prerequisites

### Environment Variables

Create a `.env.test` file:

```bash
# Database (local testing uses SQLite in-memory)
CORVID_DATABASE_URL="postgresql+asyncpg://corvid:corvid@localhost:5432/corvid"
CORVID_REDIS_URL="redis://localhost:6379/0"

# External APIs (required for enrichment tests)
CORVID_ABUSEIPDB_API_KEY="your-key-here"
CORVID_NVD_API_KEY="your-key-here"

# Gradient AI (required for full analysis tests)
CORVID_GRADIENT_API_KEY="your-key-here"
CORVID_GRADIENT_KB_ID="your-kb-id-here"

# For smoke tests against deployed system
CORVID_TEST_URL="https://your-app.ondigitalocean.app"

# Debug mode
CORVID_DEBUG="true"
CORVID_LOG_LEVEL="DEBUG"
```

### Required Tools

```bash
# Install test dependencies
uv pip install -e ".[dev]"

# Verify installation
uv run pytest --version
uv run python -c "import corvid; print('Corvid installed')"
```

---

## Test Categories

### Category 1: Unit Tests (Offline)

Run without external dependencies:

```bash
uv run pytest tests/unit/ tests/worker/test_normalizer.py -v
```

### Category 2: Integration Tests (Local DB)

Require local Postgres/Redis:

```bash
docker-compose up -d
uv run pytest tests/api/ tests/worker/ -v
```

### Category 3: External API Tests

Require API keys configured:

```bash
# Run with real external APIs
uv run pytest tests/worker/test_enrichment.py -v --run-external
```

### Category 4: Smoke Tests (Deployed)

Require deployed system:

```bash
CORVID_TEST_URL="https://your-app.ondigitalocean.app" \
  uv run pytest tests/smoke/ -v
```

---

## Test Cases

### TC-001: Health Check

**Objective:** Verify system health endpoint returns component status

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | GET /health | Status 200 |
| 2 | Check response body | Contains `status` field |
| 3 | Check components | Contains `db`, `redis`, `gradient` checks |

```bash
curl -s http://localhost:8000/health | jq
```

**Expected Response:**
```json
{
  "status": "ok",
  "checks": {
    "db": {"ok": true, "message": "Connected"},
    "redis": {"ok": true, "message": "Connected"},
    "gradient": {"ok": true, "message": "Not configured (optional)"}
  }
}
```

---

### TC-002: IOC Creation

**Objective:** Verify IOC creation for all supported types

| IOC Type | Test Value | Expected Status |
|----------|------------|-----------------|
| ip | 192.168.1.100 | 201 Created |
| domain | evil.example.com | 201 Created |
| url | http://malware.test/payload | 201 Created |
| hash_md5 | d41d8cd98f00b204e9800998ecf8427e | 201 Created |
| hash_sha1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 | 201 Created |
| hash_sha256 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | 201 Created |
| email | attacker@evil.com | 201 Created |

```bash
# Test IP creation
curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "192.168.1.100", "tags": ["test"]}' | jq
```

---

### TC-003: IOC Validation

**Objective:** Verify invalid IOCs are rejected

| Test | Input | Expected Status | Expected Error |
|------|-------|-----------------|----------------|
| Invalid IP | 999.999.999.999 | 422 | Validation error |
| Invalid hash length | abc123 | 422 | Validation error |
| Empty value | "" | 422 | Validation error |
| Unknown type | "invalid_type" | 422 | Validation error |

```bash
# Test invalid IP
curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "not-an-ip"}' | jq
```

---

### TC-004: IOC Deduplication

**Objective:** Verify duplicate IOCs update existing record

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Create IOC with value X | New record created |
| 2 | Create IOC with same value X | Existing record updated |
| 3 | Check `last_seen` timestamp | Updated to current time |

```bash
# Create first
curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "10.0.0.1"}' | jq '.id'

# Create duplicate
curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "10.0.0.1"}' | jq '.id'

# Should return same ID
```

---

### TC-005: IOC Enrichment

**Objective:** Verify enrichment fetches data from external sources

| Source | IOC Type | Expected Fields |
|--------|----------|-----------------|
| AbuseIPDB | ip | abuse_confidence_score, country_code |
| URLhaus | url, domain, ip | threat_type, url_count |
| NVD | all | cve_count, cve_ids |

```bash
# Create and enrich an IP
IOC_ID=$(curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "8.8.8.8"}' | jq -r '.id')

curl -s -X POST "http://localhost:8000/api/v1/iocs/$IOC_ID/enrich" | jq
```

**Expected Response:**
```json
{
  "ioc_id": "uuid",
  "results": [
    {
      "source": "abuseipdb",
      "success": true,
      "summary": "AbuseIPDB: 0% confidence, 0 reports"
    },
    {
      "source": "urlhaus",
      "success": true,
      "summary": "URLhaus: No matches found"
    }
  ]
}
```

---

### TC-006: AI Analysis

**Objective:** Verify Gradient agent produces structured analysis

| Field | Validation |
|-------|------------|
| severity | 0.0 - 10.0 |
| confidence | 0.0 - 1.0 |
| related_cves | CVE-YYYY-NNNNN format |
| mitre_techniques | TNNNN or TNNNN.NNN format |
| recommended_actions | Non-empty list |

```bash
curl -s -X POST http://localhost:8000/api/v1/analyses/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [{"type": "ip", "value": "185.220.101.1"}],
    "context": "Found in firewall logs at 3am",
    "priority": "high"
  }' | jq
```

**Expected Response:**
```json
{
  "analysis_id": "uuid",
  "status": "completed",
  "results": [
    {
      "ioc": {"type": "ip", "value": "185.220.101.1", "tags": []},
      "severity": 7.5,
      "confidence": 0.8,
      "summary": "This IP is associated with...",
      "related_cves": ["CVE-2024-..."],
      "mitre_techniques": ["T1071.001"],
      "enrichments": {...},
      "recommended_actions": ["Block at firewall", "..."]
    }
  ]
}
```

---

### TC-007: Analysis Retrieval

**Objective:** Verify stored analyses can be retrieved

```bash
# Get analysis by ID
ANALYSIS_ID="uuid-from-previous-test"
curl -s "http://localhost:8000/api/v1/analyses/$ANALYSIS_ID" | jq
```

---

### TC-008: Defanging/Normalization

**Objective:** Verify defanged IOCs are properly normalized

| Input (Defanged) | Expected (Normalized) |
|------------------|----------------------|
| hxxp://evil[.]com | http://evil.com |
| 192[.]168[.]1[.]1 | 192.168.1.1 |
| test[@]evil[.]com | test@evil.com |
| hxxps://bad[.]site/path | https://bad.site/path |

```bash
# Create with defanged value
curl -s -X POST http://localhost:8000/api/v1/iocs/ \
  -H "Content-Type: application/json" \
  -d '{"type": "url", "value": "hxxp://evil[.]com/malware"}' | jq '.value'

# Should return normalized: "http://evil.com/malware"
```

---

### TC-009: Pagination

**Objective:** Verify IOC listing supports pagination

```bash
# Get first page
curl -s "http://localhost:8000/api/v1/iocs/?limit=10&skip=0" | jq '.total, .items | length'

# Get second page
curl -s "http://localhost:8000/api/v1/iocs/?limit=10&skip=10" | jq '.items | length'
```

---

### TC-010: Type Filtering

**Objective:** Verify IOC listing can filter by type

```bash
# Get only IP IOCs
curl -s "http://localhost:8000/api/v1/iocs/?type=ip" | jq '.items[].type' | sort | uniq
# Should only show "ip"
```

---

## Test Data

### Safe Test IOCs

These IOCs are safe for testing and won't trigger real security alerts:

```json
{
  "safe_ips": [
    "192.0.2.1",
    "192.0.2.50",
    "198.51.100.1",
    "203.0.113.1",
    "8.8.8.8",
    "1.1.1.1"
  ],
  "safe_domains": [
    "example.com",
    "example.org",
    "test.example.net"
  ],
  "safe_urls": [
    "http://example.com/test",
    "https://httpbin.org/get"
  ],
  "safe_hashes": {
    "empty_file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "empty_file_md5": "d41d8cd98f00b204e9800998ecf8427e",
    "eicar_sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  }
}
```

### Known Suspicious IOCs (For Enrichment Testing)

These may trigger alerts from threat intel sources:

```json
{
  "tor_exit_nodes": [
    "185.220.101.1",
    "185.220.101.33",
    "185.220.101.46"
  ],
  "test_malicious_domains": [
    "malware.testdomain.com"
  ]
}
```

### Bulk Test Data Generator

```python
#!/usr/bin/env python3
"""Generate test IOCs for bulk testing."""

import json
import random
import hashlib

def generate_test_iocs(count: int = 100) -> list[dict]:
    """Generate random test IOCs."""
    iocs = []

    for i in range(count):
        ioc_type = random.choice(["ip", "domain", "hash_sha256"])

        if ioc_type == "ip":
            # Use TEST-NET ranges (safe)
            value = f"192.0.2.{random.randint(1, 254)}"
        elif ioc_type == "domain":
            value = f"test{i}.example.com"
        else:
            # Generate random hash
            value = hashlib.sha256(f"test{i}".encode()).hexdigest()

        iocs.append({
            "type": ioc_type,
            "value": value,
            "tags": ["bulk-test", f"batch-{i // 10}"]
        })

    return iocs

if __name__ == "__main__":
    iocs = generate_test_iocs(100)
    print(json.dumps(iocs, indent=2))
```

Save as `scripts/generate_test_data.py` and run:

```bash
python scripts/generate_test_data.py > test_iocs.json
```

---

## Automated Test Scripts

### Script 1: Full Test Suite

```bash
#!/bin/bash
# scripts/run_all_tests.sh
# Run the complete test suite

set -e

echo "=========================================="
echo "Corvid Full Test Suite"
echo "=========================================="

# Check prerequisites
echo -e "\n[1/5] Checking prerequisites..."
docker-compose ps | grep -q "Up" || {
    echo "Starting Docker containers..."
    docker-compose up -d
    sleep 5
}

# Run unit tests
echo -e "\n[2/5] Running unit tests..."
uv run pytest tests/unit/ tests/worker/test_normalizer.py -v --tb=short

# Run integration tests
echo -e "\n[3/5] Running integration tests..."
uv run pytest tests/api/ tests/worker/test_orchestrator.py -v --tb=short

# Run Phase 3 tests
echo -e "\n[4/5] Running Phase 3 tests (agent + ingestion)..."
uv run pytest tests/agent/ tests/ingestion/ -v --tb=short

# Run Phase 4 tests
echo -e "\n[5/5] Running Phase 4 tests (health + deployment)..."
uv run pytest tests/api/test_health.py -v --tb=short

echo -e "\n=========================================="
echo "All tests completed successfully!"
echo "=========================================="
```

### Script 2: Smoke Test Runner

```bash
#!/bin/bash
# scripts/run_smoke_tests.sh
# Run smoke tests against deployed system

set -e

CORVID_TEST_URL="${CORVID_TEST_URL:-}"

if [ -z "$CORVID_TEST_URL" ]; then
    echo "Error: CORVID_TEST_URL environment variable not set"
    echo "Usage: CORVID_TEST_URL=https://your-app.ondigitalocean.app ./scripts/run_smoke_tests.sh"
    exit 1
fi

echo "=========================================="
echo "Corvid Smoke Tests"
echo "Target: $CORVID_TEST_URL"
echo "=========================================="

# Health check first
echo -e "\n[1/6] Health Check..."
HEALTH=$(curl -sf "$CORVID_TEST_URL/health")
STATUS=$(echo "$HEALTH" | jq -r '.status')
echo "Health status: $STATUS"

if [ "$STATUS" != "ok" ] && [ "$STATUS" != "degraded" ]; then
    echo "Error: Health check failed"
    echo "$HEALTH" | jq
    exit 1
fi

# Run pytest smoke tests
echo -e "\n[2/6] Running smoke test suite..."
CORVID_TEST_URL="$CORVID_TEST_URL" uv run pytest tests/smoke/ -v

echo -e "\n=========================================="
echo "Smoke tests completed!"
echo "=========================================="
```

### Script 3: API Endpoint Tester

```bash
#!/bin/bash
# scripts/test_api_endpoints.sh
# Test all API endpoints manually

BASE_URL="${1:-http://localhost:8000}"

echo "Testing Corvid API at $BASE_URL"
echo "================================"

# Health
echo -e "\n[1] GET /health"
curl -s "$BASE_URL/health" | jq

# Create IOC
echo -e "\n[2] POST /api/v1/iocs/"
IOC_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "192.0.2.100", "tags": ["test"]}')
echo "$IOC_RESPONSE" | jq
IOC_ID=$(echo "$IOC_RESPONSE" | jq -r '.id')

# List IOCs
echo -e "\n[3] GET /api/v1/iocs/"
curl -s "$BASE_URL/api/v1/iocs/?limit=5" | jq

# Get single IOC
echo -e "\n[4] GET /api/v1/iocs/$IOC_ID"
curl -s "$BASE_URL/api/v1/iocs/$IOC_ID" | jq

# Enrich IOC
echo -e "\n[5] POST /api/v1/iocs/$IOC_ID/enrich"
curl -s -X POST "$BASE_URL/api/v1/iocs/$IOC_ID/enrich" | jq

# Analyze IOC
echo -e "\n[6] POST /api/v1/analyses/analyze"
ANALYSIS_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/analyses/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [{"type": "ip", "value": "192.0.2.100"}],
    "context": "API test",
    "priority": "low"
  }')
echo "$ANALYSIS_RESPONSE" | jq
ANALYSIS_ID=$(echo "$ANALYSIS_RESPONSE" | jq -r '.analysis_id')

# Get analysis
echo -e "\n[7] GET /api/v1/analyses/$ANALYSIS_ID"
curl -s "$BASE_URL/api/v1/analyses/$ANALYSIS_ID" | jq

# Delete test IOC
echo -e "\n[8] DELETE /api/v1/iocs/$IOC_ID"
curl -s -X DELETE "$BASE_URL/api/v1/iocs/$IOC_ID"
echo "Deleted"

echo -e "\n================================"
echo "API endpoint tests completed!"
```

### Script 4: Load Test

```python
#!/usr/bin/env python3
"""
scripts/load_test.py
Simple load test for Corvid API
"""

import asyncio
import time
import httpx
import statistics

BASE_URL = "http://localhost:8000"
CONCURRENT_REQUESTS = 10
TOTAL_REQUESTS = 100


async def make_request(client: httpx.AsyncClient, endpoint: str) -> float:
    """Make a request and return response time."""
    start = time.time()
    await client.get(f"{BASE_URL}{endpoint}")
    return time.time() - start


async def run_load_test():
    """Run concurrent requests and measure performance."""
    print(f"Load Test: {TOTAL_REQUESTS} requests, {CONCURRENT_REQUESTS} concurrent")
    print("=" * 50)

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Warm up
        await client.get(f"{BASE_URL}/health")

        # Health endpoint test
        print("\n[1] Testing GET /health")
        times = []
        for batch in range(TOTAL_REQUESTS // CONCURRENT_REQUESTS):
            tasks = [make_request(client, "/health") for _ in range(CONCURRENT_REQUESTS)]
            batch_times = await asyncio.gather(*tasks)
            times.extend(batch_times)

        print(f"  Requests: {len(times)}")
        print(f"  Avg: {statistics.mean(times)*1000:.1f}ms")
        print(f"  P50: {statistics.median(times)*1000:.1f}ms")
        print(f"  P95: {sorted(times)[int(len(times)*0.95)]*1000:.1f}ms")
        print(f"  Max: {max(times)*1000:.1f}ms")

        # IOC list test
        print("\n[2] Testing GET /api/v1/iocs/")
        times = []
        for batch in range(TOTAL_REQUESTS // CONCURRENT_REQUESTS):
            tasks = [make_request(client, "/api/v1/iocs/") for _ in range(CONCURRENT_REQUESTS)]
            batch_times = await asyncio.gather(*tasks)
            times.extend(batch_times)

        print(f"  Requests: {len(times)}")
        print(f"  Avg: {statistics.mean(times)*1000:.1f}ms")
        print(f"  P50: {statistics.median(times)*1000:.1f}ms")
        print(f"  P95: {sorted(times)[int(len(times)*0.95)]*1000:.1f}ms")
        print(f"  Max: {max(times)*1000:.1f}ms")

    print("\n" + "=" * 50)
    print("Load test completed!")


if __name__ == "__main__":
    asyncio.run(run_load_test())
```

---

## Manual Testing Procedures

### Procedure 1: New Deployment Verification

1. **Verify Health**
   ```bash
   curl -s https://your-app.ondigitalocean.app/health | jq
   ```
   - [ ] Status is "ok" or "degraded"
   - [ ] DB check shows "ok": true
   - [ ] Redis check shows "ok": true

2. **Verify API Docs**
   - [ ] Visit https://your-app.ondigitalocean.app/docs
   - [ ] Swagger UI loads correctly
   - [ ] All endpoints are listed

3. **Create Test IOC**
   ```bash
   curl -X POST https://your-app.ondigitalocean.app/api/v1/iocs/ \
     -H "Content-Type: application/json" \
     -d '{"type": "ip", "value": "192.0.2.1", "tags": ["deploy-test"]}'
   ```
   - [ ] Returns 201 status
   - [ ] Response includes UUID

4. **Verify Enrichment**
   - [ ] Trigger enrichment on created IOC
   - [ ] At least one source returns successfully

5. **Verify Analysis**
   - [ ] Submit IOC for analysis
   - [ ] Response includes severity and confidence
   - [ ] Response includes recommended actions

### Procedure 2: Regression Testing After Updates

1. Run full automated test suite
2. Run smoke tests against staging
3. Verify no new errors in logs
4. Check response times haven't degraded

---

## Expected Results

### Response Time Benchmarks

| Endpoint | Target P95 | Max Acceptable |
|----------|------------|----------------|
| GET /health | < 100ms | 500ms |
| GET /api/v1/iocs/ | < 200ms | 1s |
| POST /api/v1/iocs/ | < 300ms | 1s |
| POST /enrich | < 10s | 30s |
| POST /analyze | < 30s | 120s |

### Success Criteria

| Test Category | Pass Threshold |
|---------------|----------------|
| Unit Tests | 100% pass |
| Integration Tests | 100% pass |
| API Tests | 100% pass |
| Smoke Tests | 100% pass |
| Load Tests | P95 < target |

---

## Troubleshooting

### Common Issues

#### Tests Fail with Database Connection Error

```bash
# Check Docker containers
docker-compose ps

# Restart if needed
docker-compose down && docker-compose up -d

# Verify connection
psql "postgresql://corvid:corvid@localhost:5432/corvid" -c "SELECT 1"
```

#### Enrichment Tests Return Empty Results

```bash
# Verify API keys are set
echo $CORVID_ABUSEIPDB_API_KEY
echo $CORVID_NVD_API_KEY

# Test API key directly
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" \
  -H "Key: $CORVID_ABUSEIPDB_API_KEY" | jq
```

#### Smoke Tests Skipped

```bash
# Ensure URL is set
export CORVID_TEST_URL="https://your-app.ondigitalocean.app"

# Verify URL is accessible
curl -s "$CORVID_TEST_URL/health"
```

#### Analysis Returns Mock Response

The agent returns mock responses when Gradient API is not configured:

```bash
# Check Gradient configuration
echo $CORVID_GRADIENT_API_KEY
echo $CORVID_GRADIENT_KB_ID
```

### Log Analysis

```bash
# View application logs (local)
docker-compose logs -f api

# View logs (DigitalOcean)
doctl apps logs <app-id> --follow

# Filter for errors
doctl apps logs <app-id> | grep -i error
```

---

## Appendix: Quick Reference

### Run All Tests

```bash
uv run pytest -v
```

### Run Specific Phase

```bash
uv run pytest -m phase1 -v  # Foundation
uv run pytest -m phase2 -v  # Enrichment
uv run pytest -m phase3 -v  # Agent
uv run pytest -m phase4 -v  # Deployment
```

### Generate Coverage Report

```bash
uv run pytest --cov=corvid --cov-report=html
open htmlcov/index.html
```

### Test Single File

```bash
uv run pytest tests/api/test_analyze.py -v
```

### Test With Verbose Output

```bash
uv run pytest -v --tb=long -s
```
