"""Knowledge base ingestion pipeline.

Modules for fetching security data from external sources and
preparing it for the Gradient knowledge base.

Sources:
    - NVD: National Vulnerability Database CVEs
    - MITRE: ATT&CK Enterprise techniques
    - CISA KEV: Known Exploited Vulnerabilities catalog
"""

from corvid.ingestion.advisories import (
    KEVDocument,
    fetch_cisa_kev,
    fetch_kev_by_cve_id,
    get_ransomware_cves,
    is_kev_cve,
)
from corvid.ingestion.loader import (
    KBDocument,
    build_knowledge_base,
    fetch_all_sources,
    prepare_kb_documents,
    upload_to_gradient_kb,
)
from corvid.ingestion.mitre import (
    MITREDocument,
    fetch_mitre_attack,
    fetch_technique_by_id,
)
from corvid.ingestion.nvd import (
    CVEDocument,
    fetch_cve_by_id,
    fetch_nvd_cves,
)

__all__ = [
    # NVD
    "CVEDocument",
    "fetch_nvd_cves",
    "fetch_cve_by_id",
    # MITRE
    "MITREDocument",
    "fetch_mitre_attack",
    "fetch_technique_by_id",
    # CISA KEV
    "KEVDocument",
    "fetch_cisa_kev",
    "fetch_kev_by_cve_id",
    "is_kev_cve",
    "get_ransomware_cves",
    # Loader
    "KBDocument",
    "build_knowledge_base",
    "fetch_all_sources",
    "prepare_kb_documents",
    "upload_to_gradient_kb",
]
