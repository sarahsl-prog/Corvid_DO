"""Tests for the knowledge base ingestion pipeline.

Tests NVD CVE parsing, MITRE ATT&CK parsing, CISA KEV parsing,
and the loader/coordinator functionality.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from corvid.ingestion.nvd import (
    CVEDocument,
    _parse_cve,
    _extract_cvss_info,
    fetch_nvd_cves,
)
from corvid.ingestion.mitre import (
    MITREDocument,
    _parse_technique,
    _build_tactic_map,
    fetch_mitre_attack,
)
from corvid.ingestion.advisories import (
    KEVDocument,
    _parse_kev_entry,
    fetch_cisa_kev,
)
from corvid.ingestion.loader import (
    prepare_kb_documents,
    _deduplicate_documents,
)


# Sample NVD API response for a CVE
SAMPLE_NVD_CVE = {
    "cve": {
        "id": "CVE-2024-21762",
        "descriptions": [
            {"lang": "en", "value": "A out-of-bounds write in Fortinet FortiOS."}
        ],
        "published": "2024-02-09T12:00:00.000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
        "references": [
            {"url": "https://fortiguard.com/advisory/FG-IR-24-015"}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*"}
                        ]
                    }
                ]
            }
        ],
    }
}

# Sample NVD CVE with missing fields
SAMPLE_NVD_CVE_INCOMPLETE = {
    "cve": {
        "id": "CVE-2024-99999",
        "descriptions": [],
        "metrics": {},
    }
}

# Sample MITRE ATT&CK STIX bundle (simplified)
SAMPLE_STIX_BUNDLE = {
    "objects": [
        {
            "type": "x-mitre-tactic",
            "name": "Command and Control",
            "x_mitre_shortname": "command-and-control",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern-001",
            "name": "Application Layer Protocol",
            "description": "Adversaries may communicate using application layer protocols.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1071", "url": "https://attack.mitre.org/techniques/T1071"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
            ],
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "x_mitre_data_sources": ["Network Traffic"],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern-002",
            "name": "Web Protocols",
            "description": "Sub-technique using HTTP/HTTPS.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1071.001"}
            ],
            "x_mitre_platforms": ["Windows"],
            "revoked": False,
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern-revoked",
            "name": "Revoked Technique",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
        },
        {
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "mitigation-001",
            "target_ref": "attack-pattern-001",
        },
        {
            "type": "course-of-action",
            "id": "mitigation-001",
            "name": "Network Intrusion Prevention",
        },
    ]
}

# Sample CISA KEV entry
SAMPLE_KEV_ENTRY = {
    "cveID": "CVE-2024-21762",
    "vendorProject": "Fortinet",
    "product": "FortiOS",
    "vulnerabilityName": "Fortinet FortiOS Out-of-Bound Write Vulnerability",
    "shortDescription": "Fortinet FortiOS contains an out-of-bound write vulnerability.",
    "dateAdded": "2024-02-09",
    "dueDate": "2024-02-16",
    "requiredAction": "Apply mitigations per vendor instructions.",
    "knownRansomwareCampaignUse": "Known",
    "notes": "This CVE has been used in ransomware attacks.",
}


@pytest.mark.phase3
class TestNVDIngestion:
    """Tests for NVD CVE document parsing."""

    def test_nvd_document_parsing(self):
        """Test parsing a complete NVD CVE response into CVEDocument."""
        doc = _parse_cve(SAMPLE_NVD_CVE)

        assert doc is not None
        assert doc.cve_id == "CVE-2024-21762"
        assert "out-of-bounds write" in doc.description.lower()
        assert doc.cvss_score == 9.8
        assert doc.severity == "CRITICAL"
        assert doc.published == "2024-02-09"
        assert len(doc.references) > 0
        assert "fortiguard.com" in doc.references[0]
        assert len(doc.affected_products) > 0
        assert "fortinet:fortios" in doc.affected_products[0]
        # Content should combine all fields
        assert "CVE-2024-21762" in doc.content
        assert "CRITICAL" in doc.content

    def test_nvd_handles_missing_fields(self):
        """Test parsing CVE with missing CVSS score and description."""
        doc = _parse_cve(SAMPLE_NVD_CVE_INCOMPLETE)

        assert doc is not None
        assert doc.cve_id == "CVE-2024-99999"
        assert doc.description == ""  # Empty when no descriptions
        assert doc.cvss_score is None  # None when no metrics
        assert doc.severity == "NONE"

    @pytest.mark.asyncio
    async def test_nvd_pagination(self):
        """Test that NVD fetcher handles multi-page responses."""
        # Mock two pages of results
        page1_response = {
            "totalResults": 3,
            "vulnerabilities": [SAMPLE_NVD_CVE, SAMPLE_NVD_CVE_INCOMPLETE],
        }
        page2_response = {
            "totalResults": 3,
            "vulnerabilities": [SAMPLE_NVD_CVE],
        }

        with patch("corvid.ingestion.nvd.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            # Return different responses for each call
            mock_response1 = MagicMock()
            mock_response1.json.return_value = page1_response
            mock_response1.raise_for_status = MagicMock()

            mock_response2 = MagicMock()
            mock_response2.json.return_value = page2_response
            mock_response2.raise_for_status = MagicMock()

            mock_instance.get.side_effect = [mock_response1, mock_response2]

            docs = await fetch_nvd_cves(years=1, max_results=5)

            # Should have fetched both pages
            assert len(docs) == 3


@pytest.mark.phase3
class TestMITREIngestion:
    """Tests for MITRE ATT&CK technique parsing."""

    def test_mitre_technique_parsing(self):
        """Test parsing a MITRE ATT&CK technique from STIX bundle."""
        tactic_map = _build_tactic_map(SAMPLE_STIX_BUNDLE["objects"])
        mitigation_map = {"attack-pattern-001": ["Network Intrusion Prevention"]}

        technique_obj = SAMPLE_STIX_BUNDLE["objects"][1]  # T1071
        doc = _parse_technique(technique_obj, tactic_map, mitigation_map)

        assert doc is not None
        assert doc.technique_id == "T1071"
        assert doc.name == "Application Layer Protocol"
        assert "application layer protocols" in doc.description.lower()
        assert "Command and Control" in doc.tactics
        assert "Windows" in doc.platforms
        assert "Network Traffic" in doc.data_sources
        assert "Network Intrusion Prevention" in doc.mitigations
        assert doc.url == "https://attack.mitre.org/techniques/T1071"
        # Content should be populated
        assert "T1071" in doc.content

    def test_mitre_filters_revoked(self):
        """Test that revoked techniques are filtered out."""
        tactic_map = {}
        mitigation_map = {}

        revoked_obj = SAMPLE_STIX_BUNDLE["objects"][3]  # Revoked technique
        doc = _parse_technique(revoked_obj, tactic_map, mitigation_map)

        assert doc is None  # Should be filtered out

    @pytest.mark.asyncio
    async def test_mitre_filters_enterprise_only(self):
        """Test that only Enterprise ATT&CK techniques are included."""
        with patch("corvid.ingestion.mitre.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_STIX_BUNDLE
            mock_response.raise_for_status = MagicMock()
            mock_instance.get.return_value = mock_response

            docs = await fetch_mitre_attack(include_subtechniques=True)

            # Should have 2 valid techniques (T1071 and T1071.001), not the revoked one
            assert len(docs) == 2
            technique_ids = [d.technique_id for d in docs]
            assert "T1071" in technique_ids
            assert "T1071.001" in technique_ids
            assert "T9999" not in technique_ids  # Revoked


@pytest.mark.phase3
class TestKEVIngestion:
    """Tests for CISA KEV catalog parsing."""

    def test_kev_parsing(self):
        """Test parsing a CISA KEV entry into KEVDocument."""
        doc = _parse_kev_entry(SAMPLE_KEV_ENTRY)

        assert doc is not None
        assert doc.cve_id == "CVE-2024-21762"
        assert doc.vendor_project == "Fortinet"
        assert doc.product == "FortiOS"
        assert "Out-of-Bound Write" in doc.vulnerability_name
        assert doc.date_added == "2024-02-09"
        assert doc.due_date == "2024-02-16"
        assert "Apply mitigations" in doc.required_action
        assert doc.known_ransomware_use is True
        assert "ransomware" in doc.notes.lower()
        # Content should contain key info
        assert "CVE-2024-21762" in doc.content
        assert "ransomware" in doc.content.lower()

    @pytest.mark.asyncio
    async def test_kev_fetch(self):
        """Test fetching CISA KEV catalog."""
        mock_kev_response = {
            "catalogVersion": "2024.02.09",
            "dateReleased": "2024-02-09",
            "vulnerabilities": [SAMPLE_KEV_ENTRY],
        }

        with patch("corvid.ingestion.advisories.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_kev_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.get.return_value = mock_response

            docs = await fetch_cisa_kev()

            assert len(docs) == 1
            assert docs[0].cve_id == "CVE-2024-21762"


@pytest.mark.phase3
class TestLoader:
    """Tests for the knowledge base loader/coordinator."""

    def test_loader_deduplicates(self):
        """Test that CVEs from NVD and KEV are deduplicated."""
        cve_docs = [
            CVEDocument(
                cve_id="CVE-2024-21762",
                description="Test CVE",
                cvss_score=9.8,
                severity="CRITICAL",
            ),
            CVEDocument(
                cve_id="CVE-2024-11111",
                description="Another CVE",
                cvss_score=5.0,
                severity="MEDIUM",
            ),
        ]

        kev_docs = [
            KEVDocument(
                cve_id="CVE-2024-21762",
                vendor_project="Fortinet",
                product="FortiOS",
                vulnerability_name="Test",
                short_description="Test",
                date_added="2024-02-09",
                due_date="2024-02-16",
                required_action="Apply patch",
                known_ransomware_use=True,
            )
        ]

        deduped_cves, kev_ids = _deduplicate_documents(cve_docs, kev_docs)

        # Should have same CVEs but with KEV ID noted
        assert len(deduped_cves) == 2
        assert "CVE-2024-21762" in kev_ids

    def test_loader_combines_all_sources(self):
        """Test that loader combines documents from all sources."""
        cve_docs = [
            CVEDocument(
                cve_id="CVE-2024-11111",
                description="Test",
                cvss_score=5.0,
                severity="MEDIUM",
            )
        ]
        mitre_docs = [
            MITREDocument(
                technique_id="T1071",
                name="Test Technique",
                description="Test",
            )
        ]
        kev_docs = [
            KEVDocument(
                cve_id="CVE-2024-22222",
                vendor_project="Test",
                product="Test",
                vulnerability_name="Test",
                short_description="Test",
                date_added="2024-01-01",
                due_date="2024-01-08",
                required_action="Test",
                known_ransomware_use=False,
            )
        ]

        kb_docs = prepare_kb_documents(cve_docs, mitre_docs, kev_docs)

        # Should have 1 CVE + 1 MITRE + 1 KEV = 3 docs
        assert len(kb_docs) == 3
        doc_types = [d.doc_type for d in kb_docs]
        assert "cve" in doc_types
        assert "mitre_technique" in doc_types
        assert "kev" in doc_types
