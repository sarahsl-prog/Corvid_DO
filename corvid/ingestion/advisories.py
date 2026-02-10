"""CISA Known Exploited Vulnerabilities (KEV) ingestion module.

Fetches the CISA KEV catalog and formats entries as documents
for the Gradient knowledge base. Cross-references with NVD data
where available.

Scope: ~1,200 KEV entries - high-value dataset for identifying
actively exploited vulnerabilities.
"""

from dataclasses import dataclass, field
from datetime import datetime

import httpx
from loguru import logger

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass
class KEVDocument:
    """A CISA KEV entry document for knowledge base ingestion."""

    cve_id: str  # "CVE-2024-21762"
    vendor_project: str  # "Fortinet"
    product: str  # "FortiOS"
    vulnerability_name: str  # "Fortinet FortiOS Out-of-Bound Write Vulnerability"
    short_description: str
    date_added: str  # ISO date when added to KEV
    due_date: str  # Remediation due date for federal agencies
    required_action: str  # Specific remediation action required
    known_ransomware_use: bool  # Whether used in ransomware campaigns
    notes: str = ""
    content: str = ""  # Full text for embedding

    def __post_init__(self) -> None:
        """Generate the content field from other fields."""
        if not self.content:
            self.content = self._build_content()

    def _build_content(self) -> str:
        """Build searchable content text from all fields."""
        parts = [
            f"CISA Known Exploited Vulnerability: {self.cve_id}",
            f"Vendor: {self.vendor_project}",
            f"Product: {self.product}",
            f"Vulnerability: {self.vulnerability_name}",
            f"Description: {self.short_description}",
            f"Date Added to KEV: {self.date_added}",
            f"Remediation Due Date: {self.due_date}",
            f"Required Action: {self.required_action}",
        ]
        if self.known_ransomware_use:
            parts.append("WARNING: Known to be used in ransomware campaigns")
        if self.notes:
            parts.append(f"Notes: {self.notes}")
        return "\n".join(parts)


def _parse_kev_entry(entry: dict) -> KEVDocument | None:
    """Parse a single KEV entry into a KEVDocument.

    Args:
        entry: A vulnerability entry from the KEV JSON.

    Returns:
        KEVDocument if parsing succeeds, None otherwise.
    """
    cve_id = entry.get("cveID", "")
    if not cve_id:
        return None

    vendor = entry.get("vendorProject", "Unknown")
    product = entry.get("product", "Unknown")
    vuln_name = entry.get("vulnerabilityName", "")
    description = entry.get("shortDescription", "")
    date_added = entry.get("dateAdded", "")
    due_date = entry.get("dueDate", "")
    required_action = entry.get("requiredAction", "")
    notes = entry.get("notes", "")

    # Parse ransomware usage - can be "Known", "Unknown", or missing
    ransomware_str = entry.get("knownRansomwareCampaignUse", "Unknown")
    known_ransomware = ransomware_str.lower() == "known"

    return KEVDocument(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name=vuln_name,
        short_description=description,
        date_added=date_added,
        due_date=due_date,
        required_action=required_action,
        known_ransomware_use=known_ransomware,
        notes=notes,
    )


async def fetch_cisa_kev() -> list[KEVDocument]:
    """Fetch the CISA Known Exploited Vulnerabilities catalog.

    Returns:
        List of KEVDocument objects ready for knowledge base upload.
    """
    logger.info("Fetching CISA KEV catalog")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            logger.error("Failed to fetch CISA KEV catalog: {}", e)
            return []

    # Extract metadata
    catalog_version = data.get("catalogVersion", "unknown")
    date_released = data.get("dateReleased", "unknown")
    logger.info(
        "CISA KEV catalog version {} released {}",
        catalog_version,
        date_released,
    )

    vulnerabilities = data.get("vulnerabilities", [])
    documents: list[KEVDocument] = []

    for entry in vulnerabilities:
        doc = _parse_kev_entry(entry)
        if doc:
            documents.append(doc)

    # Sort by date added (most recent first)
    documents.sort(key=lambda d: d.date_added, reverse=True)

    logger.info("CISA KEV ingestion complete: {} vulnerability documents", len(documents))
    return documents


async def fetch_kev_by_cve_id(cve_id: str) -> KEVDocument | None:
    """Check if a CVE is in the CISA KEV catalog.

    Args:
        cve_id: The CVE ID to look up (e.g., "CVE-2024-21762").

    Returns:
        KEVDocument if found in KEV, None otherwise.
    """
    documents = await fetch_cisa_kev()
    for doc in documents:
        if doc.cve_id.upper() == cve_id.upper():
            return doc
    return None


def is_kev_cve(cve_id: str, kev_docs: list[KEVDocument]) -> bool:
    """Check if a CVE ID is in a list of KEV documents.

    Args:
        cve_id: The CVE ID to check.
        kev_docs: Pre-fetched list of KEV documents.

    Returns:
        True if the CVE is in the KEV catalog.
    """
    cve_upper = cve_id.upper()
    return any(doc.cve_id.upper() == cve_upper for doc in kev_docs)


def get_ransomware_cves(kev_docs: list[KEVDocument]) -> list[KEVDocument]:
    """Filter KEV documents to only those known to be used in ransomware.

    Args:
        kev_docs: List of KEV documents.

    Returns:
        List of KEV documents with known ransomware usage.
    """
    return [doc for doc in kev_docs if doc.known_ransomware_use]
