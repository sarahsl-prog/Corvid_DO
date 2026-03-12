"""Extended tests for corvid/ingestion/loader.py.

Covers:
- fetch_from_local_file (single file + directory)
- fetch_all_sources
- upload_to_gradient_kb (success, no api key, no kb_id, HTTP error, batching)
- build_knowledge_base (dry-run and upload paths)
- _cve_to_kb_doc, _mitre_to_kb_doc, _kev_to_kb_doc helper functions
"""

import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvid.ingestion.advisories import KEVDocument
from corvid.ingestion.loader import (
    KBDocument,
    _cve_to_kb_doc,
    _kev_to_kb_doc,
    _mitre_to_kb_doc,
    build_knowledge_base,
    fetch_all_sources,
    fetch_from_local_file,
    prepare_kb_documents,
    upload_to_gradient_kb,
)
from corvid.ingestion.mitre import MITREDocument
from corvid.ingestion.nvd import CVEDocument


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_cve(cve_id: str = "CVE-2024-11111") -> CVEDocument:
    return CVEDocument(
        cve_id=cve_id,
        description="Test CVE description",
        cvss_score=7.5,
        severity="HIGH",
    )


def _make_mitre(technique_id: str = "T1071") -> MITREDocument:
    return MITREDocument(
        technique_id=technique_id,
        name="Application Layer Protocol",
        description="C2 over application protocols",
    )


def _make_kev(cve_id: str = "CVE-2024-22222") -> KEVDocument:
    return KEVDocument(
        cve_id=cve_id,
        vendor_project="Acme",
        product="Widget",
        vulnerability_name="Acme Widget RCE",
        short_description="Remote code execution",
        date_added="2024-01-01",
        due_date="2024-01-08",
        required_action="Apply patch",
        known_ransomware_use=False,
    )


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestConversionHelpers:
    """Tests for _cve_to_kb_doc, _mitre_to_kb_doc, _kev_to_kb_doc."""

    def test_cve_to_kb_doc(self):
        cve = _make_cve()
        doc = _cve_to_kb_doc(cve, is_kev=True)

        assert isinstance(doc, KBDocument)
        assert doc.doc_type == "cve"
        assert doc.id == "CVE-2024-11111"
        assert doc.metadata["is_kev"] is True
        assert doc.metadata["cvss_score"] == 7.5

    def test_cve_to_kb_doc_not_kev(self):
        cve = _make_cve()
        doc = _cve_to_kb_doc(cve, is_kev=False)
        assert doc.metadata["is_kev"] is False

    def test_mitre_to_kb_doc(self):
        mitre = _make_mitre()
        doc = _mitre_to_kb_doc(mitre)

        assert doc.doc_type == "mitre_technique"
        assert doc.id == "T1071"
        assert "tactics" in doc.metadata
        assert "platforms" in doc.metadata

    def test_kev_to_kb_doc(self):
        kev = _make_kev()
        doc = _kev_to_kb_doc(kev)

        assert doc.doc_type == "kev"
        assert doc.id == "KEV-CVE-2024-22222"
        assert doc.metadata["vendor"] == "Acme"
        assert doc.metadata["ransomware"] is False


# ---------------------------------------------------------------------------
# fetch_from_local_file
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestFetchFromLocalFile:
    """Tests for loading CVE documents from local JSON files."""

    def _cve_schema_record(self, cve_id: str) -> dict:
        """Return a single CVE schema record (CVE List V5 format)."""
        return {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": cve_id, "datePublished": "2024-01-15T00:00:00Z"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                    "affected": [],
                    "references": [],
                }
            },
        }

    @pytest.mark.asyncio
    async def test_single_file_cve_schema_format(self, tmp_path):
        """Parses a JSON file in CVE schema (CVE List V5) format."""
        data = self._cve_schema_record("CVE-2024-55555")
        json_file = tmp_path / "cves.json"
        json_file.write_text(json.dumps(data))

        docs = await fetch_from_local_file(str(json_file))
        assert len(docs) == 1
        assert docs[0].cve_id == "CVE-2024-55555"

    @pytest.mark.asyncio
    async def test_directory_of_json_files(self, tmp_path):
        """Scans a directory for JSON files and parses each."""
        for i in range(3):
            data = self._cve_schema_record(f"CVE-2024-6000{i}")
            (tmp_path / f"cve_{i}.json").write_text(json.dumps(data))

        docs = await fetch_from_local_file(str(tmp_path))
        assert len(docs) == 3

    @pytest.mark.asyncio
    async def test_directory_skips_invalid_json(self, tmp_path):
        """Files that fail to parse are skipped with a warning."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json {{{{")

        good_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-77777",
                        "descriptions": [{"lang": "en", "value": "Good CVE"}],
                        "metrics": {},
                    }
                }
            ]
        }
        (tmp_path / "good.json").write_text(json.dumps(good_data))

        docs = await fetch_from_local_file(str(tmp_path))
        # Only the parseable file contributes documents
        assert all(d.cve_id == "CVE-2024-77777" for d in docs)


# ---------------------------------------------------------------------------
# fetch_all_sources
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestFetchAllSources:
    """Tests for fetch_all_sources coordinator."""

    @pytest.mark.asyncio
    async def test_fetch_all_sources_combines_results(self):
        cve_docs = [_make_cve("CVE-2024-11111")]
        mitre_docs = [_make_mitre("T1071")]
        kev_docs = [_make_kev("CVE-2024-22222")]

        with (
            patch(
                "corvid.ingestion.loader.fetch_nvd_cves",
                new=AsyncMock(return_value=cve_docs),
            ),
            patch(
                "corvid.ingestion.loader.fetch_mitre_attack",
                new=AsyncMock(return_value=mitre_docs),
            ),
            patch(
                "corvid.ingestion.loader.fetch_cisa_kev",
                new=AsyncMock(return_value=kev_docs),
            ),
        ):
            result_cves, result_mitres, result_kevs = await fetch_all_sources(
                nvd_years=1,
                nvd_api_key=None,
                include_mitre_subtechniques=True,
            )

        assert len(result_cves) == 1
        assert len(result_mitres) == 1
        assert len(result_kevs) == 1


# ---------------------------------------------------------------------------
# upload_to_gradient_kb
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestUploadToGradientKB:
    """Tests for upload_to_gradient_kb."""

    @pytest.mark.asyncio
    async def test_upload_skipped_without_api_key(self):
        """Returns False and skips upload when no API key configured."""
        docs = [_cve_to_kb_doc(_make_cve())]

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = "some-kb-id"
            mock_settings.gradient_kb_url = ""

            result = await upload_to_gradient_kb(docs, api_key="", kb_id="some-kb-id")

        assert result is False

    @pytest.mark.asyncio
    async def test_upload_skipped_without_kb_id(self):
        """Returns False and skips upload when no KB ID configured."""
        docs = [_cve_to_kb_doc(_make_cve())]

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_api_key = "some-key"
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_kb_url = ""

            result = await upload_to_gradient_kb(docs, api_key="some-key", kb_id="")

        assert result is False

    @pytest.mark.asyncio
    async def test_upload_success(self):
        """Returns True on successful batch upload."""
        docs = [_cve_to_kb_doc(_make_cve("CVE-2024-11111"))]

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.post.return_value = mock_resp

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_kb_url = ""

            with patch("corvid.ingestion.loader.httpx.AsyncClient", mock_client):
                result = await upload_to_gradient_kb(
                    docs, api_key="valid-key", kb_id="valid-kb-id"
                )

        assert result is True
        mock_instance.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_uses_custom_kb_url(self):
        """Uses custom gradient_kb_url when configured."""
        docs = [_cve_to_kb_doc(_make_cve("CVE-2024-11111"))]

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.post.return_value = mock_resp

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_kb_url = "https://custom.kb.example.com/v1/knowledge-bases/my-kb"

            with patch("corvid.ingestion.loader.httpx.AsyncClient", mock_client):
                result = await upload_to_gradient_kb(
                    docs, api_key="valid-key", kb_id="valid-kb-id"
                )

        assert result is True
        call_url = mock_instance.post.call_args[0][0]
        assert "custom.kb.example.com" in call_url

    @pytest.mark.asyncio
    async def test_upload_fails_on_http_error(self):
        """Returns False when an HTTP error occurs during batch upload."""
        import httpx

        docs = [_cve_to_kb_doc(_make_cve("CVE-2024-11111"))]

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.post.side_effect = httpx.HTTPError("connection refused")

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_kb_url = ""

            with patch("corvid.ingestion.loader.httpx.AsyncClient", mock_client):
                result = await upload_to_gradient_kb(
                    docs, api_key="valid-key", kb_id="valid-kb-id"
                )

        assert result is False

    @pytest.mark.asyncio
    async def test_upload_multiple_batches(self):
        """Batches large document sets into multiple POST requests."""
        docs = [_cve_to_kb_doc(_make_cve(f"CVE-2024-{i:05d}")) for i in range(5)]

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.post.return_value = mock_resp

        with patch("corvid.ingestion.loader.settings") as mock_settings:
            mock_settings.gradient_kb_url = ""

            with patch("corvid.ingestion.loader.httpx.AsyncClient", mock_client):
                result = await upload_to_gradient_kb(
                    docs, api_key="valid-key", kb_id="valid-kb-id", batch_size=2
                )

        assert result is True
        # 5 docs / 2 per batch = 3 batches
        assert mock_instance.post.call_count == 3


# ---------------------------------------------------------------------------
# build_knowledge_base
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestBuildKnowledgeBase:
    """Tests for the top-level build_knowledge_base function."""

    @pytest.mark.asyncio
    async def test_build_dry_run(self):
        """Dry run returns prepared documents without uploading."""
        cve_docs = [_make_cve("CVE-2024-11111")]
        mitre_docs = [_make_mitre("T1071")]
        kev_docs = [_make_kev("CVE-2024-22222")]

        with (
            patch(
                "corvid.ingestion.loader.fetch_all_sources",
                new=AsyncMock(return_value=(cve_docs, mitre_docs, kev_docs)),
            ),
            patch(
                "corvid.ingestion.loader.upload_to_gradient_kb",
                new=AsyncMock(return_value=True),
            ) as mock_upload,
            patch("corvid.ingestion.loader.settings") as mock_settings,
        ):
            mock_settings.nvd_api_key = ""

            docs = await build_knowledge_base(nvd_years=1, upload=False)

        # 1 CVE + 1 MITRE + 1 KEV = 3
        assert len(docs) == 3
        mock_upload.assert_not_called()

    @pytest.mark.asyncio
    async def test_build_with_upload(self):
        """When upload=True, calls upload_to_gradient_kb."""
        cve_docs = [_make_cve("CVE-2024-11111")]
        mitre_docs = []
        kev_docs = []

        with (
            patch(
                "corvid.ingestion.loader.fetch_all_sources",
                new=AsyncMock(return_value=(cve_docs, mitre_docs, kev_docs)),
            ),
            patch(
                "corvid.ingestion.loader.upload_to_gradient_kb",
                new=AsyncMock(return_value=True),
            ) as mock_upload,
            patch("corvid.ingestion.loader.settings") as mock_settings,
        ):
            mock_settings.nvd_api_key = ""

            docs = await build_knowledge_base(nvd_years=1, upload=True)

        mock_upload.assert_called_once()
        assert len(docs) == 1

    @pytest.mark.asyncio
    async def test_build_upload_failure_logged(self):
        """When upload fails, function still returns the prepared docs."""
        cve_docs = [_make_cve("CVE-2024-11111")]

        with (
            patch(
                "corvid.ingestion.loader.fetch_all_sources",
                new=AsyncMock(return_value=(cve_docs, [], [])),
            ),
            patch(
                "corvid.ingestion.loader.upload_to_gradient_kb",
                new=AsyncMock(return_value=False),  # Upload fails
            ),
            patch("corvid.ingestion.loader.settings") as mock_settings,
        ):
            mock_settings.nvd_api_key = ""
            docs = await build_knowledge_base(upload=True)

        # Should still return docs even when upload fails
        assert len(docs) == 1
