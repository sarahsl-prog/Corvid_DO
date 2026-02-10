"""Tests for SQLAlchemy ORM model instantiation.

These are unit tests that verify model construction without a database.
PostgreSQL-specific features (JSONB, ARRAY) are tested via integration
tests with a real Postgres instance.
"""

import uuid

from corvid.db.models import Analysis, CVEReference, Enrichment, IOC


class TestIOCModel:
    """Tests for the IOC ORM model."""

    def test_create_ioc_instance(self) -> None:
        ioc = IOC(
            id=uuid.uuid4(),
            type="ip",
            value="192.168.1.1",
            tags=["test"],
            severity_score=5.0,
        )
        assert ioc.type == "ip"
        assert ioc.value == "192.168.1.1"
        assert ioc.severity_score == 5.0
        assert ioc.tags == ["test"]

    def test_ioc_defaults(self) -> None:
        ioc = IOC(type="domain", value="evil.example.com")
        assert ioc.id is None  # Set by DB default
        assert ioc.severity_score is None

    def test_ioc_all_types(self) -> None:
        types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"]
        for ioc_type in types:
            ioc = IOC(type=ioc_type, value="test")
            assert ioc.type == ioc_type


class TestEnrichmentModel:
    """Tests for the Enrichment ORM model."""

    def test_create_enrichment_instance(self) -> None:
        ioc_id = uuid.uuid4()
        enrichment = Enrichment(
            id=uuid.uuid4(),
            ioc_id=ioc_id,
            source="virustotal",
            raw_response={"positives": 15, "total": 70},
            summary="15/70 engines flagged this file.",
        )
        assert enrichment.source == "virustotal"
        assert enrichment.raw_response["positives"] == 15

    def test_enrichment_defaults(self) -> None:
        enrichment = Enrichment(
            ioc_id=uuid.uuid4(),
            source="abuseipdb",
            raw_response={},
        )
        assert enrichment.summary is None
        assert enrichment.ttl_expires_at is None


class TestAnalysisModel:
    """Tests for the Analysis ORM model."""

    def test_create_analysis_instance(self) -> None:
        analysis = Analysis(
            id=uuid.uuid4(),
            ioc_ids=[uuid.uuid4()],
            analysis_text="This IP is associated with known C2 infrastructure.",
            confidence=0.85,
            mitre_techniques=["T1071.001"],
            recommended_actions=["Block at firewall"],
            model_version="gradient-v1",
        )
        assert analysis.confidence == 0.85
        assert "T1071.001" in analysis.mitre_techniques

    def test_analysis_defaults(self) -> None:
        analysis = Analysis(
            analysis_text="Test",
            confidence=0.5,
        )
        assert analysis.agent_trace_id is None
        assert analysis.model_version is None


class TestCVEReferenceModel:
    """Tests for the CVEReference ORM model."""

    def test_create_cve_reference(self) -> None:
        ref = CVEReference(
            id=uuid.uuid4(),
            cve_id="CVE-2024-21762",
            cvss_score=9.8,
            description="FortiOS out-of-bound write vulnerability",
        )
        assert ref.cve_id == "CVE-2024-21762"
        assert ref.cvss_score == 9.8

    def test_cve_nullable_foreign_keys(self) -> None:
        ref = CVEReference(
            cve_id="CVE-2024-0001",
            ioc_id=None,
            analysis_id=None,
        )
        assert ref.ioc_id is None
        assert ref.analysis_id is None
