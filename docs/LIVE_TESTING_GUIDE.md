# Corvid Live System Testing Guide

This guide provides commands and sample data for testing the Corvid threat intelligence platform against a running instance.

## Prerequisites

### 1. Environment Variables

Create a `.env` file or export these variables:

```bash
# Required for database
export CORVID_DATABASE_URL="postgresql+asyncpg://corvid:corvid@localhost:5432/corvid"
export CORVID_REDIS_URL="redis://localhost:6379/0"

# Optional - enables external enrichment (get free API keys)
export CORVID_ABUSEIPDB_API_KEY="your-abuseipdb-key"  # https://www.abuseipdb.com/api
export CORVID_NVD_API_KEY="your-nvd-key"              # https://nvd.nist.gov/developers/request-an-api-key

# Optional - enables Gradient AI agent (required for full /analyze functionality)
export CORVID_GRADIENT_API_KEY="your-gradient-key"
export CORVID_GRADIENT_KB_ID="your-kb-id"
```

### 2. Start the System

```bash
# Start infrastructure (Postgres + Redis)
docker-compose up -d

# Run database migrations
uv run alembic upgrade head

# Start the API server
uv run uvicorn corvid.api.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Base URL

All commands below assume:
```bash
export BASE_URL="http://localhost:8000"
```

---

## Test 1: Health Check

Verify the API is running and can connect to dependencies.

```bash
curl -s $BASE_URL/health | jq
```

**Expected Response:**
```json
{
  "status": "ok"
}
```

---

## Test 2: Create IOCs

### 2.1 Create an IP IOC

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip",
    "value": "185.220.101.1",
    "tags": ["tor-exit", "suspicious"]
  }' | jq
```

**Expected Response:**
```json
{
  "id": "uuid-here",
  "type": "ip",
  "value": "185.220.101.1",
  "first_seen": "2024-...",
  "last_seen": "2024-...",
  "tags": ["tor-exit", "suspicious"],
  "severity_score": null,
  "created_at": "...",
  "updated_at": "..."
}
```

### 2.2 Create a Domain IOC

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "domain",
    "value": "malware.testdomain.com",
    "tags": ["phishing"]
  }' | jq
```

### 2.3 Create a Hash IOC

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "hash_sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tags": ["malware-sample"]
  }' | jq
```

### 2.4 Create a URL IOC

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "url",
    "value": "http://evil.example.com/malware.exe",
    "tags": ["malware-distribution"]
  }' | jq
```

---

## Test 3: List and Retrieve IOCs

### 3.1 List All IOCs

```bash
curl -s "$BASE_URL/api/v1/iocs/" | jq
```

### 3.2 Filter by Type

```bash
curl -s "$BASE_URL/api/v1/iocs/?type=ip" | jq
```

### 3.3 Get Single IOC

Replace `{ioc_id}` with an actual UUID from the create response:

```bash
curl -s "$BASE_URL/api/v1/iocs/{ioc_id}" | jq
```

---

## Test 4: Trigger Enrichment

Enrichment fetches threat intelligence from external sources (AbuseIPDB, URLhaus, NVD).

### 4.1 Enrich an IP

First create an IP, then trigger enrichment:

```bash
# Create
IOC_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "8.8.8.8", "tags": ["test"]}')

IOC_ID=$(echo $IOC_RESPONSE | jq -r '.id')
echo "Created IOC: $IOC_ID"

# Enrich
curl -s -X POST "$BASE_URL/api/v1/iocs/$IOC_ID/enrich" | jq
```

**Expected Response (with API keys configured):**
```json
{
  "ioc_id": "...",
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

### 4.2 Enrich a Known Malicious IP

Test with a known bad IP (Tor exit node):

```bash
# Create
IOC_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "185.220.101.1", "tags": ["tor"]}')

IOC_ID=$(echo $IOC_RESPONSE | jq -r '.id')

# Enrich
curl -s -X POST "$BASE_URL/api/v1/iocs/$IOC_ID/enrich" | jq
```

---

## Test 5: AI-Powered Analysis (Phase 3)

The `/analyze` endpoint uses the Gradient AI agent to produce comprehensive threat analysis.

### 5.1 Analyze a Single IP

```bash
curl -s -X POST "$BASE_URL/api/v1/analyses/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {"type": "ip", "value": "185.220.101.1"}
    ],
    "context": "Observed in outbound traffic from web server at 3am",
    "priority": "high"
  }' | jq
```

**Expected Response:**
```json
{
  "analysis_id": "uuid-here",
  "status": "completed",
  "results": [
    {
      "ioc": {"type": "ip", "value": "185.220.101.1", "tags": []},
      "severity": 7.5,
      "confidence": 0.8,
      "summary": "This IP is associated with...",
      "related_cves": ["CVE-2024-..."],
      "mitre_techniques": ["T1071.001"],
      "enrichments": {
        "abuseipdb": {"summary": "...", "raw": {...}}
      },
      "recommended_actions": [
        "Block at firewall",
        "Review logs for lateral movement"
      ]
    }
  ]
}
```

### 5.2 Analyze Multiple IOCs

```bash
curl -s -X POST "$BASE_URL/api/v1/analyses/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {"type": "ip", "value": "185.220.101.1"},
      {"type": "domain", "value": "evil.example.com"},
      {"type": "hash_sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    ],
    "context": "Found in phishing email campaign targeting finance department",
    "priority": "high"
  }' | jq
```

### 5.3 Retrieve a Stored Analysis

```bash
curl -s "$BASE_URL/api/v1/analyses/{analysis_id}" | jq
```

---

## Test 6: Knowledge Base Ingestion

Run the ingestion pipeline to populate the Gradient knowledge base with CVEs, MITRE techniques, and KEV entries.

### 6.1 Dry Run (No Upload)

```bash
uv run python -m corvid.ingestion.loader --dry-run --years=1
```

**Expected Output:**
```
2024-... | INFO | Fetching NVD CVEs from 2023-... to 2024-...
2024-... | INFO | NVD reports 15000 total CVEs in date range
2024-... | INFO | Fetching MITRE ATT&CK Enterprise STIX bundle
2024-... | INFO | MITRE ATT&CK ingestion complete: 700 technique documents
2024-... | INFO | Fetching CISA KEV catalog
2024-... | INFO | CISA KEV ingestion complete: 1200 vulnerability documents
2024-... | INFO | Total documents for KB: 16900
2024-... | INFO | Dry run - skipping KB upload
```

### 6.2 Full Ingestion (With Upload)

Requires `CORVID_GRADIENT_API_KEY` and `CORVID_GRADIENT_KB_ID`:

```bash
uv run python -m corvid.ingestion.loader --years=2
```

---

## Test 7: Sample IOCs for Testing

### Known Malicious/Suspicious IPs

```bash
# Tor exit nodes (frequently flagged)
185.220.101.1
185.220.101.33
185.220.101.46

# Known C2 servers (check current threat feeds)
# Note: These may change - verify with current intel
```

### Test Domains

```bash
# Safe test domains (won't trigger alerts)
example.com
test.example.org

# For testing defanging
evil[.]example[.]com  # Will be normalized to evil.example.com
hxxps://malware[.]test[.]com/payload  # Will be normalized
```

### Test Hashes

```bash
# Empty file SHA256 (safe, commonly known)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# EICAR test file SHA256 (AV test signature)
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Test URLs

```bash
# Safe test URLs
http://example.com/test
https://httpbin.org/get

# Defanged format (will be normalized)
hxxp://evil[.]example[.]com/malware.exe
```

---

## Test 8: Validation Tests

### 8.1 Invalid IOC Type (Should Return 422)

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "invalid_type", "value": "test"}' | jq
```

### 8.2 Invalid IP Format (Should Return 422)

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "not.an.ip"}' | jq
```

### 8.3 Invalid Hash Length (Should Return 422)

```bash
curl -s -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "hash_sha256", "value": "tooshort"}' | jq
```

---

## Test 9: Full End-to-End Test Script

Save this as `test_corvid.sh` and run it:

```bash
#!/bin/bash
set -e

BASE_URL="${BASE_URL:-http://localhost:8000}"
echo "Testing Corvid at $BASE_URL"
echo "================================"

# Health check
echo -e "\n[1/5] Health Check..."
curl -sf "$BASE_URL/health" | jq -e '.status == "ok"' > /dev/null
echo "✓ Health check passed"

# Create IOC
echo -e "\n[2/5] Creating IOC..."
IOC_RESPONSE=$(curl -sf -X POST "$BASE_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "192.0.2.1", "tags": ["test"]}')
IOC_ID=$(echo $IOC_RESPONSE | jq -r '.id')
echo "✓ Created IOC: $IOC_ID"

# List IOCs
echo -e "\n[3/5] Listing IOCs..."
LIST_RESPONSE=$(curl -sf "$BASE_URL/api/v1/iocs/")
TOTAL=$(echo $LIST_RESPONSE | jq '.total')
echo "✓ Found $TOTAL IOC(s)"

# Trigger enrichment
echo -e "\n[4/5] Triggering Enrichment..."
ENRICH_RESPONSE=$(curl -sf -X POST "$BASE_URL/api/v1/iocs/$IOC_ID/enrich")
RESULTS=$(echo $ENRICH_RESPONSE | jq '.results | length')
echo "✓ Enrichment returned $RESULTS result(s)"

# Analyze IOC
echo -e "\n[5/5] Running Analysis..."
ANALYZE_RESPONSE=$(curl -sf -X POST "$BASE_URL/api/v1/analyses/analyze" \
  -H "Content-Type: application/json" \
  -d '{"iocs": [{"type": "ip", "value": "192.0.2.1"}], "context": "Test analysis"}')
STATUS=$(echo $ANALYZE_RESPONSE | jq -r '.status')
ANALYSIS_ID=$(echo $ANALYZE_RESPONSE | jq -r '.analysis_id')
echo "✓ Analysis completed with status: $STATUS (ID: $ANALYSIS_ID)"

# Cleanup
echo -e "\n[Cleanup] Deleting test IOC..."
curl -sf -X DELETE "$BASE_URL/api/v1/iocs/$IOC_ID" > /dev/null
echo "✓ Deleted IOC"

echo -e "\n================================"
echo "All tests passed! ✓"
```

Make executable and run:

```bash
chmod +x test_corvid.sh
./test_corvid.sh
```

---

## Troubleshooting

### API Returns 500 Errors

Check the server logs for details:
```bash
# If running with uvicorn directly
# Logs appear in terminal

# Check database connection
uv run python -c "from corvid.db.session import async_session; print('DB OK')"
```

### Enrichment Returns Empty Results

1. Check API keys are set:
   ```bash
   echo $CORVID_ABUSEIPDB_API_KEY
   echo $CORVID_NVD_API_KEY
   ```

2. Test API key validity:
   ```bash
   # AbuseIPDB
   curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" \
     -H "Key: $CORVID_ABUSEIPDB_API_KEY" | jq
   ```

### Analysis Returns Mock Response

If `CORVID_GRADIENT_API_KEY` is not set, the agent returns a mock response. Check:
```bash
echo $CORVID_GRADIENT_API_KEY
echo $CORVID_GRADIENT_KB_ID
```

### Database Connection Failed

```bash
# Check Postgres is running
docker-compose ps

# Check connection string
echo $CORVID_DATABASE_URL

# Test connection
uv run python -c "
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from corvid.config import settings

async def test():
    engine = create_async_engine(settings.database_url)
    async with engine.connect() as conn:
        result = await conn.execute('SELECT 1')
        print('Database connection OK')

asyncio.run(test())
"
```

---

## API Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/iocs/` | GET | List IOCs (query: `type`, `skip`, `limit`) |
| `/api/v1/iocs/` | POST | Create IOC |
| `/api/v1/iocs/{id}` | GET | Get single IOC |
| `/api/v1/iocs/{id}` | DELETE | Delete IOC |
| `/api/v1/iocs/{id}/enrich` | POST | Trigger enrichment |
| `/api/v1/analyses/analyze` | POST | AI-powered analysis |
| `/api/v1/analyses/{id}` | GET | Get stored analysis |
| `/docs` | GET | OpenAPI/Swagger UI |
| `/redoc` | GET | ReDoc API documentation |
