# End-to-End Tests for Digital Ocean Deployment

This directory contains comprehensive end-to-end tests designed to verify the Corvid platform when deployed on DigitalOcean App Platform.

## Overview

These tests validate:
- **Deployment Health**: App is reachable, all components healthy
- **IOC Management**: CRUD operations, deduplication, pagination
- **Enrichment Pipeline**: External API integration, provider availability
- **AI Analysis**: Full analysis workflow, batch processing, result retrieval
- **Performance**: Response times, concurrent request handling
- **Error Handling**: Validation, 404s, edge cases
- **Data Persistence**: Database operations across requests

## Prerequisites

1. **Deployed Application**: Corvid must be deployed and running on Digital Ocean
2. **Environment Variable**: Set `CORVID_TEST_URL` to your app's URL
3. **Test Dependencies**: Install with `pip install httpx pytest`

## Running the Tests

### Against Digital Ocean Deployment

```bash
# Set your deployed app URL
export CORVID_TEST_URL=https://corvid-abc123.ondigitalocean.app

# Run all e2e tests
pytest tests/e2e/ -v

# Run specific test class
pytest tests/e2e/test_do_deployment.py::TestIOCManagement -v

# Run with detailed output
pytest tests/e2e/ -vv -s

# Generate HTML test report
pytest tests/e2e/ --html=report.html --self-contained-html
```

### Against Local Development

```bash
# Start local Docker containers first
docker-compose up -d

# Run tests against local instance
export CORVID_TEST_URL=http://localhost:8000
pytest tests/e2e/ -v
```

## Test Categories

### 1. Deployment Health Tests
**Class**: `TestDeploymentHealth`

Validates basic deployment health and configuration:
- App is reachable and responding
- Health check reports all components
- OpenAPI documentation accessible
- CORS headers configured

```bash
pytest tests/e2e/test_do_deployment.py::TestDeploymentHealth -v
```

### 2. IOC Management Tests
**Class**: `TestIOCManagement`

Tests CRUD operations for IOCs:
- Create and retrieve IOCs
- List with pagination
- Deduplication logic
- Tag merging

```bash
pytest tests/e2e/test_do_deployment.py::TestIOCManagement -v
```

### 3. Enrichment Pipeline Tests
**Class**: `TestEnrichmentPipeline`

Validates external API integration:
- IP address enrichment
- Provider availability (AbuseIPDB, URLhaus, NVD)
- Error handling when providers fail

```bash
pytest tests/e2e/test_do_deployment.py::TestEnrichmentPipeline -v
```

### 4. AI Analysis Tests
**Class**: `TestAnalysisEndpoint`

Tests the full AI-powered analysis workflow:
- Single IOC analysis
- Batch analysis (multiple IOCs)
- Analysis retrieval by ID
- Response structure validation

```bash
pytest tests/e2e/test_do_deployment.py::TestAnalysisEndpoint -v
```

### 5. Performance Tests
**Class**: `TestPerformance`

Benchmarks response times and load handling:
- Health check < 1s
- IOC creation < 2s
- Concurrent request handling

```bash
pytest tests/e2e/test_do_deployment.py::TestPerformance -v
```

### 6. Error Handling Tests
**Class**: `TestErrorHandling`

Validates proper error responses:
- Invalid IOC types (422)
- Malformed values (422)
- Nonexistent resources (404)

```bash
pytest tests/e2e/test_do_deployment.py::TestErrorHandling -v
```

### 7. Data Persistence Tests
**Class**: `TestDataPersistence`

Verifies database operations:
- IOC data persists across requests
- Analysis results stored correctly
- Data consistency

```bash
pytest tests/e2e/test_do_deployment.py::TestDataPersistence -v
```

## Expected Results

### Passing Tests (100%)
All tests should pass when the deployment is healthy:
```
tests/e2e/test_do_deployment.py::TestDeploymentHealth::test_app_is_reachable PASSED
tests/e2e/test_do_deployment.py::TestDeploymentHealth::test_health_check_components PASSED
tests/e2e/test_do_deployment.py::TestDeploymentHealth::test_openapi_schema_accessible PASSED
...
============================== 30+ passed in X.XXs ==============================
```

### Partial Failures
Some tests may fail if:
- **Gradient API unavailable**: Analysis tests may fail but return graceful errors
- **External APIs rate-limited**: Enrichment tests may have partial failures
- **First-time deployment**: Database may need migrations

## Troubleshooting

### All Tests Skipped
```
SKIPPED [X] - CORVID_TEST_URL environment variable not set
```
**Solution**: Set `CORVID_TEST_URL` environment variable

### Connection Errors
```
httpx.ConnectError: [Errno 61] Connection refused
```
**Solution**: Verify the app URL is correct and deployment is running

### Timeout Errors
```
httpx.TimeoutException: Request timeout
```
**Solution**: Increase timeout or check if app is under heavy load

### 500 Internal Server Errors
```
assert response.status_code == 200
AssertionError: assert 500 == 200
```
**Solution**: Check app logs on Digital Ocean:
```bash
doctl apps logs <app-id> --follow
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: E2E Tests (Digital Ocean)
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install httpx pytest pytest-html

      - name: Run E2E tests
        env:
          CORVID_TEST_URL: ${{ secrets.CORVID_STAGING_URL }}
        run: |
          pytest tests/e2e/ -v --html=e2e-report.html --self-contained-html

      - name: Upload test report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: e2e-test-report
          path: e2e-report.html
```

## Test Data Cleanup

Tests automatically clean up data they create:
- IOCs created during tests are deleted afterward
- Analysis records remain in DB (for audit trail)
- Use tags like `e2e-test`, `do-deployment` for easy identification

To manually clean up test data:
```sql
DELETE FROM iocs WHERE 'e2e-test' = ANY(tags);
```

## Performance Benchmarks

Expected response times on Digital Ocean (basic-xxs instance):
- Health check: < 1 second
- IOC creation: < 2 seconds
- IOC enrichment: 10-30 seconds (depending on external APIs)
- AI analysis (single IOC): 30-60 seconds
- AI analysis (batch): 1-3 minutes

## Adding New Tests

To add new e2e tests:

1. Add test methods to existing classes or create new test class
2. Follow naming convention: `test_*`
3. Use descriptive docstrings
4. Clean up any created resources in `finally` blocks
5. Use appropriate timeouts for long-running operations

Example:
```python
class TestNewFeature:
    """Test description."""

    def test_new_functionality(self, client: httpx.Client, base_url: str) -> None:
        """Test new feature works end-to-end."""
        # Test implementation
        pass
```

## Related Documentation

- [Deployment Guide](../../deploy/README.md)
- [Smoke Tests](../smoke/test_deployed.py)
- [Testing Plan](../TESTING_PLAN.md)
