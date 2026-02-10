"""Agent tools for the Gradient-powered Corvid threat analyst.

Each tool can be called by the Gradient agent during IOC analysis.
Tools handle database lookups, external API enrichment, CVE search,
and knowledge base semantic search.
"""

from corvid.agent.tools.enrich_external import (
    ENRICH_EXTERNAL_SCHEMA,
    enrich_ioc_external,
    get_available_sources,
)
from corvid.agent.tools.lookup_ioc import (
    LOOKUP_IOC_SCHEMA,
    lookup_ioc,
)
from corvid.agent.tools.search_cves import (
    SEARCH_CVES_SCHEMA,
    get_cve_details,
    search_cves,
)
from corvid.agent.tools.search_kb import (
    SEARCH_KB_SCHEMA,
    get_kev_status,
    search_cve_advisories,
    search_knowledge_base,
    search_mitre_techniques,
)

__all__ = [
    # Lookup IOC
    "lookup_ioc",
    "LOOKUP_IOC_SCHEMA",
    # Search CVEs
    "search_cves",
    "get_cve_details",
    "SEARCH_CVES_SCHEMA",
    # Enrich External
    "enrich_ioc_external",
    "get_available_sources",
    "ENRICH_EXTERNAL_SCHEMA",
    # Search KB
    "search_knowledge_base",
    "search_mitre_techniques",
    "search_cve_advisories",
    "get_kev_status",
    "SEARCH_KB_SCHEMA",
]

# Collect all tool schemas for agent registration
TOOL_SCHEMAS = [
    LOOKUP_IOC_SCHEMA,
    SEARCH_CVES_SCHEMA,
    ENRICH_EXTERNAL_SCHEMA,
    SEARCH_KB_SCHEMA,
]
