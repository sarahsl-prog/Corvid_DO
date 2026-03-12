"""Extended tests for corvid/ingestion/nvd.py.

Covers:
- CVSS 3.0 and 2.0 fallback scoring in _extract_cvss_info
- _parse_cve edge cases (empty cve_data, no CVE id)
- fetch_nvd_cves HTTP error handling and max_results truncation
- fetch_cve_by_id (found and not found)
- parse_cve_schema_json with various formats (single record, array, unknown)
- _parse_cve_schema_record with cvssV3_1, cvssMetricV31, cvssMetricV30, ADP metrics
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvid.ingestion.nvd import (
    CVEDocument,
    _extract_affected_products,
    _extract_cvss_info,
    _parse_cve,
    _parse_cve_schema_record,
    fetch_cve_by_id,
    fetch_nvd_cves,
    parse_cve_schema_json,
)


# ---------------------------------------------------------------------------
# _extract_cvss_info — fallback paths
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestExtractCVSSInfo:
    """Tests for CVSS score extraction from NVD metric blocks."""

    def test_cvss31_primary(self):
        """Prefers CVSS 3.1 Primary metric."""
        cve_data = {
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_cvss31_first_when_no_primary(self):
        """Falls back to first 3.1 entry when no Primary entry."""
        cve_data = {
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Secondary", "cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert score == 6.0
        assert severity == "MEDIUM"

    def test_cvss30_fallback(self):
        """Falls back to CVSS 3.0 when 3.1 is absent."""
        cve_data = {
            "metrics": {
                "cvssMetricV30": [
                    {"type": "Primary", "cvssData": {"baseScore": 7.2, "baseSeverity": "HIGH"}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert score == 7.2
        assert severity == "HIGH"

    def test_cvss20_fallback_high(self):
        """Falls back to CVSS 2.0 and derives severity (HIGH >= 7.0)."""
        cve_data = {
            "metrics": {
                "cvssMetricV2": [
                    {"type": "Primary", "cvssData": {"baseScore": 8.5}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert score == 8.5
        assert severity == "HIGH"

    def test_cvss20_fallback_medium(self):
        """CVSS 2.0 score >= 4.0 maps to MEDIUM."""
        cve_data = {
            "metrics": {
                "cvssMetricV2": [
                    {"type": "Primary", "cvssData": {"baseScore": 5.0}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert severity == "MEDIUM"

    def test_cvss20_fallback_low(self):
        """CVSS 2.0 score < 4.0 maps to LOW."""
        cve_data = {
            "metrics": {
                "cvssMetricV2": [
                    {"type": "Primary", "cvssData": {"baseScore": 2.1}}
                ]
            }
        }
        score, severity = _extract_cvss_info(cve_data)
        assert severity == "LOW"

    def test_no_metrics_returns_none(self):
        """Empty metrics dict returns (None, NONE)."""
        score, severity = _extract_cvss_info({})
        assert score is None
        assert severity == "NONE"


# ---------------------------------------------------------------------------
# _parse_cve edge cases
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestParseCVEEdgeCases:
    """Edge case tests for _parse_cve."""

    def test_empty_cve_data_returns_none(self):
        """Empty cve dict returns None."""
        result = _parse_cve({})
        assert result is None

    def test_missing_cve_id_returns_none(self):
        """Missing 'id' field in cve data returns None."""
        result = _parse_cve({"cve": {"descriptions": []}})
        assert result is None

    def test_cpe_with_wildcard_product_excluded(self):
        """CPE entries with wildcard product (*) are excluded from affected_products."""
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                # Wildcard product — should be excluded
                                {"criteria": "cpe:2.3:o:vendor:*:version:*:*:*:*:*:*:*"},
                                # Valid product — should be included
                                {"criteria": "cpe:2.3:a:myvendor:myproduct:1.0:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ]
        }
        products = _extract_affected_products(cve_data)
        assert "myvendor:myproduct" in products
        # Wildcard should not appear
        assert not any("*" in p for p in products)

    def test_cpe_limited_to_10(self):
        """Affected products list is limited to 10 entries."""
        cpe_matches = [
            {"criteria": f"cpe:2.3:a:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*"}
            for i in range(20)
        ]
        cve_data = {"configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}]}
        products = _extract_affected_products(cve_data)
        assert len(products) <= 10


# ---------------------------------------------------------------------------
# fetch_nvd_cves — HTTP error and max_results
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestFetchNVDCVEs:
    """Tests for fetch_nvd_cves pagination and error handling."""

    @pytest.mark.asyncio
    async def test_http_error_breaks_pagination(self):
        """HTTP errors during pagination stop the loop and return partial results."""
        import httpx

        page1 = {
            "totalResults": 5,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-11111",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {},
                    }
                }
            ],
        }

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp1 = MagicMock()
        resp1.json.return_value = page1
        resp1.raise_for_status = MagicMock()

        mock_instance.get.side_effect = [resp1, httpx.HTTPError("server error")]

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            docs = await fetch_nvd_cves(years=1)

        # Got docs from first page before error
        assert len(docs) >= 1

    @pytest.mark.asyncio
    async def test_max_results_truncates_results(self):
        """fetch_nvd_cves respects max_results limit."""
        vulnerabilities = [
            {
                "cve": {
                    "id": f"CVE-2024-{i:05d}",
                    "descriptions": [{"lang": "en", "value": f"CVE {i}"}],
                    "metrics": {},
                }
            }
            for i in range(10)
        ]

        page = {"totalResults": 10, "vulnerabilities": vulnerabilities}

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = page
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            docs = await fetch_nvd_cves(years=1, max_results=3)

        assert len(docs) <= 3

    @pytest.mark.asyncio
    async def test_empty_vulnerabilities_stops_loop(self):
        """Empty vulnerabilities list stops pagination loop."""
        page = {"totalResults": 0, "vulnerabilities": []}

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = page
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            docs = await fetch_nvd_cves(years=1)

        assert docs == []


# ---------------------------------------------------------------------------
# fetch_cve_by_id
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestFetchCVEById:
    """Tests for single-CVE lookup by ID."""

    @pytest.mark.asyncio
    async def test_found_returns_document(self):
        """Returns CVEDocument when the CVE exists."""
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-21762",
                        "descriptions": [{"lang": "en", "value": "Out-of-bounds write."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "type": "Primary",
                                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                                }
                            ]
                        },
                        "references": [],
                    }
                }
            ]
        }

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            doc = await fetch_cve_by_id("CVE-2024-21762")

        assert doc is not None
        assert doc.cve_id == "CVE-2024-21762"
        assert doc.severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        """Returns None when the CVE is not in NVD."""
        data = {"vulnerabilities": []}

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            doc = await fetch_cve_by_id("CVE-9999-99999")

        assert doc is None

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        """Returns None when an HTTP error occurs."""
        import httpx

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.side_effect = httpx.HTTPError("timeout")

        with patch("corvid.ingestion.nvd.httpx.AsyncClient", mock_client):
            doc = await fetch_cve_by_id("CVE-2024-21762")

        assert doc is None


# ---------------------------------------------------------------------------
# parse_cve_schema_json
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestParseCVESchemaJSON:
    """Tests for parse_cve_schema_json with different file structures."""

    def test_parse_cve_schema_single_record(self, tmp_path):
        """Parses a single CVE schema record (CVE List V5 format)."""
        data = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2024-11111", "datePublished": "2024-01-15T00:00:00Z"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                    "affected": [],
                    "references": [],
                }
            },
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data))

        docs = parse_cve_schema_json(str(f))
        assert len(docs) == 1
        assert docs[0].cve_id == "CVE-2024-11111"

    def test_parse_array_of_records(self, tmp_path):
        """Parses a JSON array of CVE schema records."""
        records = [
            {
                "cveMetadata": {"cveId": "CVE-2024-11111", "datePublished": "2024-01-01T00:00:00"},
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Array record CVE"}],
                        "metrics": [],
                        "affected": [],
                        "references": [],
                    }
                },
            }
        ]
        f = tmp_path / "array.json"
        f.write_text(json.dumps(records))

        docs = parse_cve_schema_json(str(f))
        assert len(docs) == 1
        assert docs[0].cve_id == "CVE-2024-11111"

    def test_parse_single_record_with_datatype(self, tmp_path):
        """Parses a single CVE schema record with dataType field."""
        record = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2024-22222", "datePublished": "2024-02-01T00:00:00"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Single record"}],
                    "metrics": [],
                    "affected": [],
                    "references": [],
                }
            },
        }
        f = tmp_path / "single.json"
        f.write_text(json.dumps(record))

        docs = parse_cve_schema_json(str(f))
        assert len(docs) == 1

    def test_parse_wrapped_records_key(self, tmp_path):
        """Parses a JSON with a top-level 'records' key."""
        data = {
            "records": [
                {
                    "cveMetadata": {
                        "cveId": "CVE-2024-33333",
                        "datePublished": "2024-03-01T00:00:00",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [{"lang": "en", "value": "Wrapped"}],
                            "metrics": [],
                            "affected": [],
                            "references": [],
                        }
                    },
                }
            ]
        }
        f = tmp_path / "wrapped.json"
        f.write_text(json.dumps(data))

        docs = parse_cve_schema_json(str(f))
        assert len(docs) == 1

    def test_unknown_structure_returns_empty(self, tmp_path):
        """Unknown JSON structure returns empty list without crash."""
        data = {"some_unknown_key": "value"}
        f = tmp_path / "unknown.json"
        f.write_text(json.dumps(data))

        docs = parse_cve_schema_json(str(f))
        assert docs == []


# ---------------------------------------------------------------------------
# _parse_cve_schema_record — metric variations
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestParseCVESchemaRecord:
    """Tests for _parse_cve_schema_record covering different CVSS paths."""

    def _base_record(self, cve_id: str = "CVE-2024-11111") -> dict:
        return {
            "cveMetadata": {"cveId": cve_id, "datePublished": "2024-01-15T00:00:00Z"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": [],
                    "affected": [],
                    "references": [],
                }
            },
        }

    def test_missing_cve_id_returns_none(self):
        """Returns None when cveId is absent."""
        record = {"cveMetadata": {}, "containers": {}}
        result = _parse_cve_schema_record(record)
        assert result is None

    def test_cvss_v3_1_format(self):
        """Parses cvssV3_1 (CVE List V5) metric format."""
        record = self._base_record()
        record["containers"]["cna"]["metrics"] = [
            {"cvssV3_1": {"baseScore": 8.0, "baseSeverity": "HIGH"}}
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert doc.cvss_score == 8.0
        assert doc.severity == "HIGH"

    def test_cvss_metric_v31_format(self):
        """Parses cvssMetricV31 (NVD API-in-record) format."""
        record = self._base_record()
        record["containers"]["cna"]["metrics"] = [
            {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}
                ]
            }
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert doc.cvss_score == 7.0

    def test_cvss_metric_v30_format(self):
        """Parses cvssMetricV30 format."""
        record = self._base_record()
        record["containers"]["cna"]["metrics"] = [
            {
                "cvssMetricV30": [
                    {"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}}
                ]
            }
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert doc.cvss_score == 6.5

    def test_adp_metrics_fallback(self):
        """Falls back to ADP metrics when CNA metrics have no score."""
        record = self._base_record()
        record["containers"]["adp"] = [
            {
                "metrics": [
                    {"cvssV3_1": {"baseScore": 5.5, "baseSeverity": "MEDIUM"}}
                ]
            }
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert doc.cvss_score == 5.5

    def test_affected_products_extracted(self):
        """Affected products with version info are extracted."""
        record = self._base_record()
        record["containers"]["cna"]["affected"] = [
            {
                "vendor": "acme",
                "product": "widget",
                "versions": [
                    {"version": "1.0"},
                    {"version": "UNKNOWN"},  # Should be excluded
                ],
            }
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert any("acme:widget" in p for p in doc.affected_products)

    def test_references_extracted(self):
        """Reference URLs are included in the document."""
        record = self._base_record()
        record["containers"]["cna"]["references"] = [
            {"url": "https://example.com/advisory"},
        ]

        doc = _parse_cve_schema_record(record)
        assert doc is not None
        assert "https://example.com/advisory" in doc.references
