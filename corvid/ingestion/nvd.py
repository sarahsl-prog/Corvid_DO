"""NVD CVE ingestion module for knowledge base population.

Fetches CVEs from the NVD 2.0 API and formats them as documents
for the Gradient knowledge base. Supports pagination and filtering
by date range.

Scope for hackathon: Last 2 years of CVEs (~20k documents).
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from loguru import logger

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # NVD max
DEFAULT_YEARS = 2


@dataclass
class CVEDocument:
    """A CVE document prepared for knowledge base ingestion."""

    cve_id: str  # "CVE-2024-21762"
    description: str  # English description text
    cvss_score: float | None  # Base score
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"
    affected_products: list[str] = field(default_factory=list)
    published: str = ""  # ISO date
    references: list[str] = field(default_factory=list)  # Reference URLs
    content: str = ""  # Full text for embedding

    def __post_init__(self) -> None:
        """Generate the content field from other fields."""
        if not self.content:
            self.content = self._build_content()

    def _build_content(self) -> str:
        """Build searchable content text from all fields."""
        parts = [
            f"CVE ID: {self.cve_id}",
            f"Severity: {self.severity}",
        ]
        if self.cvss_score is not None:
            parts.append(f"CVSS Score: {self.cvss_score}")
        if self.published:
            parts.append(f"Published: {self.published}")
        parts.append(f"Description: {self.description}")
        if self.affected_products:
            parts.append(f"Affected Products: {', '.join(self.affected_products)}")
        if self.references:
            parts.append(f"References: {', '.join(self.references[:5])}")
        return "\n".join(parts)


def _extract_cvss_info(cve_data: dict) -> tuple[float | None, str]:
    """Extract CVSS score and severity from CVE metrics.

    Tries CVSS 3.1 first, then 3.0, then 2.0.

    Args:
        cve_data: The cve object from NVD response.

    Returns:
        Tuple of (score, severity). Score may be None if not available.
    """
    metrics = cve_data.get("metrics", {})

    # Try CVSS 3.1
    cvss31 = metrics.get("cvssMetricV31", [])
    if cvss31:
        primary = next((m for m in cvss31 if m.get("type") == "Primary"), cvss31[0])
        cvss_data = primary.get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("baseSeverity", "NONE")

    # Try CVSS 3.0
    cvss30 = metrics.get("cvssMetricV30", [])
    if cvss30:
        primary = next((m for m in cvss30 if m.get("type") == "Primary"), cvss30[0])
        cvss_data = primary.get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("baseSeverity", "NONE")

    # Try CVSS 2.0
    cvss2 = metrics.get("cvssMetricV2", [])
    if cvss2:
        primary = next((m for m in cvss2 if m.get("type") == "Primary"), cvss2[0])
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")
        # CVSS 2.0 doesn't have baseSeverity, derive from score
        if score is not None:
            if score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            return score, severity

    return None, "NONE"


def _extract_affected_products(cve_data: dict) -> list[str]:
    """Extract affected product names from CPE configurations.

    Args:
        cve_data: The cve object from NVD response.

    Returns:
        List of product names (deduplicated).
    """
    products: set[str] = set()
    configurations = cve_data.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if product != "*":
                        products.add(f"{vendor}:{product}")

    return list(products)[:10]  # Limit to 10 products


def _parse_cve(vuln_item: dict) -> CVEDocument | None:
    """Parse a single CVE vulnerability item into a CVEDocument.

    Args:
        vuln_item: A vulnerability object from the NVD response.

    Returns:
        CVEDocument if parsing succeeds, None otherwise.
    """
    cve_data = vuln_item.get("cve", {})
    if not cve_data:
        return None

    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None

    # Extract English description
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Extract CVSS info
    cvss_score, severity = _extract_cvss_info(cve_data)

    # Extract published date
    published = cve_data.get("published", "")
    if published:
        # Truncate to date only
        published = published[:10]

    # Extract references (URLs)
    references = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append(url)

    # Extract affected products
    affected_products = _extract_affected_products(cve_data)

    return CVEDocument(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        severity=severity,
        affected_products=affected_products,
        published=published,
        references=references[:10],  # Limit references
    )


async def fetch_nvd_cves(
    years: int = DEFAULT_YEARS,
    api_key: str | None = None,
    start_index: int = 0,
    max_results: int | None = None,
) -> list[CVEDocument]:
    """Fetch CVEs from NVD API for the specified time range.

    Paginates through all results using the NVD 2.0 API.

    Args:
        years: Number of years back from today to fetch. Default 2.
        api_key: Optional NVD API key for higher rate limits.
        start_index: Starting index for pagination (for resuming).
        max_results: Maximum number of results to fetch. None for all.

    Returns:
        List of CVEDocument objects ready for knowledge base upload.
    """
    # Calculate date range
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=years * 365)

    pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
    pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999")

    logger.info(
        "Fetching NVD CVEs from {} to {} (years={})",
        pub_start[:10],
        pub_end[:10],
        years,
    )

    documents: list[CVEDocument] = []
    current_index = start_index
    total_results: int | None = None

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "startIndex": current_index,
                "resultsPerPage": RESULTS_PER_PAGE,
            }

            try:
                logger.debug("Fetching NVD page starting at index {}", current_index)
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as e:
                logger.error("NVD API request failed at index {}: {}", current_index, e)
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info("NVD reports {} total CVEs in date range", total_results)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                doc = _parse_cve(vuln)
                if doc:
                    documents.append(doc)

                if max_results and len(documents) >= max_results:
                    logger.info("Reached max_results limit of {}", max_results)
                    return documents

            current_index += len(vulnerabilities)
            logger.info(
                "Fetched {} CVEs so far ({} / {})",
                len(documents),
                current_index,
                total_results,
            )

            # Check if we've fetched all results
            if current_index >= (total_results or 0):
                break

            # NVD rate limit: 5 requests per 30 seconds without API key
            # With API key: 50 requests per 30 seconds
            # We don't add sleep here; caller should handle rate limiting if needed

    logger.info("NVD ingestion complete: {} CVE documents", len(documents))
    return documents


async def fetch_cve_by_id(cve_id: str, api_key: str | None = None) -> CVEDocument | None:
    """Fetch a single CVE by its ID.

    Args:
        cve_id: The CVE ID (e.g., "CVE-2024-21762").
        api_key: Optional NVD API key.

    Returns:
        CVEDocument if found, None otherwise.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                return _parse_cve(vulnerabilities[0])
            return None
        except httpx.HTTPError as e:
            logger.error("Failed to fetch CVE {}: {}", cve_id, e)
            return None


def parse_cve_schema_json(file_path: str) -> list[CVEDocument]:
    """Parse CVE records from a JSON file in CVE Schema format.

    Supports the format defined at:
    https://github.com/cveproject/cve-schema

    Args:
        file_path: Path to the JSON file containing CVE records.

    Returns:
        List of CVEDocument objects.
    """
    import json

    documents: list[CVEDocument] = []

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both single record and array of records
    records: list[dict] = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        # Check if it's a single record or wrapped in a container
        if "dataType" in data:
            records = [data]
        elif "records" in data:
            records = data["records"]
        elif "vulnerabilities" in data:
            # NVD format
            records = data["vulnerabilities"]
        else:
            logger.warning("Unknown JSON structure in {}", file_path)
            return []

    for record in records:
        doc = _parse_cve_schema_record(record)
        if doc:
            documents.append(doc)

    logger.info("Parsed {} CVE documents from {}", len(documents), file_path)
    return documents


def _parse_cve_schema_record(record: dict) -> CVEDocument | None:
    """Parse a single CVE record from CVE Schema format.

    Args:
        record: A CVE record in CVE Schema format (CVE List V5).

    Returns:
        CVEDocument if parsing succeeds, None otherwise.
    """
    # Extract CVE ID from metadata
    cve_metadata = record.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId", "")
    if not cve_id:
        return None

    # Extract description from containers.cna.descriptions
    description = ""
    containers = record.get("containers", {})
    cna = containers.get("cna", {})

    for desc in cna.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Extract CVSS score and severity
    cvss_score: float | None = None
    severity = "NONE"

    # Try metrics from CNA - handle different formats
    for metric_group in cna.get("metrics", []):
        # Format: cvssV3_1 (used in CVE List V5)
        if "cvssV3_1" in metric_group:
            cvss_data = metric_group["cvssV3_1"]
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "NONE")
            break
        # Format: cvssMetricV31 (NVD API format)
        elif "cvssMetricV31" in metric_group:
            cvss_data = metric_group["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "NONE")
            break
        # Format: cvssMetricV30
        elif "cvssMetricV30" in metric_group:
            cvss_data = metric_group["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "NONE")
            break

    # Try ADP metrics as fallback
    if cvss_score is None:
        for adp in containers.get("adp", []):
            for metric_group in adp.get("metrics", []):
                if "cvssV3_1" in metric_group:
                    cvss_data = metric_group["cvssV3_1"]
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "NONE")
                    break
            if cvss_score:
                break

    # Extract affected products
    affected_products: list[str] = []
    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "unknown")
        product = affected.get("product", "unknown")
        for version in affected.get("versions", []):
            ver = version.get("version", "")
            if ver and ver != "UNKNOWN":
                affected_products.append(f"{vendor}:{product} {ver}")

    # Extract references (URLs)
    references = []
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append(url)

    # Extract published date
    published = cve_metadata.get("datePublished", "")[:10]

    return CVEDocument(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        severity=severity,
        affected_products=affected_products[:10],
        published=published,
        references=references[:10],
    )
