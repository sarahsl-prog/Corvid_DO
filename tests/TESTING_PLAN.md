# Corvid Testing Plan

This document outlines the testing strategy for the Corvid threat intelligence platform.

## Test Categories

### 1. Unit Tests
Located in `tests/` - run with `pytest`

```bash
# Run all unit tests
pytest tests/ -v

# Run specific test file
pytest tests/worker/test_normalizer.py -v
pytest tests/api/test_iocs.py -v

# Run with coverage
pytest tests/ --cov=corvid --cov-report=html
```

### 2. Integration Tests
```bash
# Run integration tests
pytest tests/ -m integration -v

# Run e2e pipeline test
pytest tests/test_e2e_pipeline.py -v
```

### 3. Smoke Tests (Deployed App)
```bash
# Set the deployed URL
export CORVID_TEST_URL=https://your-app.ondigitalocean.app

# Run smoke tests
pytest tests/smoke/ -v
```

### 4. Manual Testing Scripts
See `tests/scripts/` for manual testing utilities.

---

## Test Data

### Sample IOCs for Testing

| Type | Value | Description |
|------|-------|-------------|
| IP (benign) | `8.8.8.8` | Google DNS |
| IP (malicious) | `185.234.219.31` | Known malicious |
| IP (private) | `192.168.1.1` | Private IP (should validate but skip enrichment) |
| Domain (benign) | `example.com` | Example domain |
| Domain (malicious) | `evil.com` | Known malicious |
| URL | `https://example.com/malware.exe` | Malicious URL |
| URL | `https://google.com` | Benign URL |
| Hash MD5 | `d41d8cd98f00b204e9800998ecf8427e` | Empty file hash |
| Hash SHA256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Empty file SHA256 |
| Email | `security@google.com` | Benign email |
| Email | `attacker@evil.com` | Malicious email |

### Create Test Data via API

```bash
# Create test IOCs
curl -X POST "$CORVID_TEST_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "8.8.8.8", "tags": ["test"]}'

curl -X POST "$CORVID_TEST_URL/api/v1/iocs/" \
  -H "Content-Type: application/json" \
  -d '{"type": "domain", "value": "example.com", "tags": ["test"]}'
```

---

## Test Scenarios

### A. IOC Management

#### A1. Create IOC - Valid Inputs
- [ ] Create IP IOC
- [ ] Create domain IOC
- [ ] Create URL IOC
- [ ] Create MD5 hash IOC
- [ ] Create SHA1 hash IOC
- [ ] Create SHA256 hash IOC
- [ ] Create email IOC

#### A2. Create IOC - Invalid Inputs
- [ ] Invalid IOC type (should return 422)
- [ ] Empty IOC value (should return 422)
- [ ] Mismatched type/value (e.g., type=ip, value=example.com) (should return 422)
- [ ] Invalid IP format (should return 422)
- [ ] Invalid hash length (should return 422)
- [ ] Invalid URL format (should return 422)
- [ ] Invalid email format (should return 422)

#### A3. Retrieve IOC
- [ ] Get IOC by ID
- [ ] Get non-existent IOC (should return 404)
- [ ] List all IOCs with pagination
- [ ] Filter IOCs by type
- [ ] Filter IOCs by tag

#### A4. Update IOC
- [ ] Add tags to IOC
- [ ] Remove tags from IOC

### B. Analysis

#### B1. Analyze Single IOC
- [ ] Analyze benign IP (8.8.8.8)
- [ ] Analyze malicious IP
- [ ] Analyze benign domain
- [ ] Analyze malicious domain
- [ ] Analyze URL
- [ ] Analyze hash (should show VirusTotal results if configured)

#### B2. Analyze Multiple IOCs
- [ ] Analyze batch of 5 IOCs
- [ ] Analyze batch of 50 IOCs

#### B3. Analysis Edge Cases
- [ ] Analyze private IP (should handle gracefully)
- [ ] Analyze reserved IP (should handle gracefully)
- [ ] Analyze very long domain (truncation)
- [ ] Analyze Unicode domain

### C. Enrichment

#### C1. External Enrichment
- [ ] AbuseIPDB enrichment (IP)
- [ ] VirusTotal enrichment (hash)
- [ ] URLhaus enrichment (URL)
- [ ] NVD enrichment (CVE lookup)

#### C2. Enrichment Caching
- [ ] First request hits external API
- [ ] Second request uses cache
- [ ] Cache expiry works correctly

#### C3. Enrichment Errors
- [ ] Handle API rate limiting (429)
- [ ] Handle API unavailable (503)
- [ ] Handle invalid API key (401)

### D. Gradient AI Agent

#### D1. Agent Analysis
- [ ] Analyze IOC with full context
- [ ] Check CVE lookup works
- [ ] Check MITRE ATT&CK techniques returned
- [ ] Check recommended actions provided

#### D2. Agent Errors
- [ ] Handle missing API key
- [ ] Handle API timeout
- [ ] Handle invalid response

### E. Performance

#### E1. Load Testing
- [ ] 100 concurrent requests
- [ ] 1000 concurrent requests

#### E2. Response Times
- [ ] Health check < 100ms
- [ ] IOC create < 500ms
- [ ] IOC retrieve < 200ms
- [ ] Analysis (with enrichment) < 30s

### F. Security

#### F1. Input Validation
- [ ] SQL injection attempt (should be sanitized)
- [ ] XSS attempt in tags (should be sanitized)
- [ ] Very large payload (should be rejected)

#### F2. Rate Limiting
- [ ] Exceed rate limit (should return 429)

---

## Running Tests

### Quick Test (5 minutes)
```bash
# Unit tests
pytest tests/unit/ -v --tb=short

# Smoke tests
CORVID_TEST_URL=https://your-app.ondigitalocean.app pytest tests/smoke/ -v
```

### Full Test Suite (30 minutes)
```bash
# All tests
pytest tests/ -v --tb=short

# With coverage
pytest tests/ --cov=corvid --cov-report=html --cov-report=term
```

### Specific Test Categories
```bash
# API tests only
pytest tests/api/ -v

# Worker tests only
pytest tests/worker/ -v

# Agent tests only
pytest tests/agent/ -v
```

---

## Test Data Scripts

See `tests/scripts/` directory:
- `create_test_data.py` - Create test IOCs
- `run_functional_tests.sh` - Run functional test suite
- `test_api_endpoints.sh` - Test all API endpoints

---

## Debugging Failed Tests

```bash
# Run with verbose output
pytest tests/ -vv -s

# Run single test
pytest tests/api/test_iocs.py::TestIOCAPI::test_create_valid_ip -vv

# Show local variables on failure
pytest tests/ -l

# Drop into debugger on failure
pytest tests/ --pdb
```

## CI/CD Integration

```bash
# GitHub Actions example
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: |
          pip install -e ".[dev]"
          pytest tests/ -v
```
