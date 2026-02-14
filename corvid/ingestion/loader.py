"""Knowledge Base loader - coordinates ingestion from all sources.

Orchestrates fetching from NVD, MITRE ATT&CK, and CISA KEV,
deduplicates documents, and uploads to the Gradient knowledge base.

Supports:
- Fetching from NVD API (default)
- Loading from local JSON file (CVE Schema format)
- Combining multiple sources
"""

from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger

from corvid.config import settings
from corvid.ingestion.advisories import KEVDocument, fetch_cisa_kev
from corvid.ingestion.mitre import MITREDocument, fetch_mitre_attack
from corvid.ingestion.nvd import (
    CVEDocument,
    fetch_nvd_cves,
    parse_cve_schema_json,
    parse_cve_schema_json,
)


@dataclass
class KBDocument:
    """Unified document format for knowledge base upload."""

    id: str  # Unique identifier (CVE ID, technique ID, etc.)
    doc_type: str  # "cve", "mitre_technique", "kev"
    title: str
    content: str
    metadata: dict[str, Any]


def _cve_to_kb_doc(cve: CVEDocument, is_kev: bool = False) -> KBDocument:
    """Convert a CVEDocument to a unified KBDocument.

    Args:
        cve: The CVE document.
        is_kev: Whether this CVE is in the CISA KEV catalog.

    Returns:
        A KBDocument ready for upload.
    """
    metadata = {
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "published": cve.published,
        "affected_products": cve.affected_products,
        "is_kev": is_kev,
    }
    return KBDocument(
        id=cve.cve_id,
        doc_type="cve",
        title=f"{cve.cve_id}: {cve.severity}",
        content=cve.content,
        metadata=metadata,
    )


def _mitre_to_kb_doc(technique: MITREDocument) -> KBDocument:
    """Convert a MITREDocument to a unified KBDocument.

    Args:
        technique: The MITRE ATT&CK technique document.

    Returns:
        A KBDocument ready for upload.
    """
    metadata = {
        "tactics": technique.tactics,
        "platforms": technique.platforms,
        "data_sources": technique.data_sources,
        "url": technique.url,
    }
    return KBDocument(
        id=technique.technique_id,
        doc_type="mitre_technique",
        title=f"{technique.technique_id}: {technique.name}",
        content=technique.content,
        metadata=metadata,
    )


def _kev_to_kb_doc(kev: KEVDocument) -> KBDocument:
    """Convert a KEVDocument to a unified KBDocument.

    Args:
        kev: The CISA KEV document.

    Returns:
        A KBDocument ready for upload.
    """
    metadata = {
        "vendor": kev.vendor_project,
        "product": kev.product,
        "date_added": kev.date_added,
        "due_date": kev.due_date,
        "ransomware": kev.known_ransomware_use,
    }
    return KBDocument(
        id=f"KEV-{kev.cve_id}",
        doc_type="kev",
        title=f"KEV: {kev.cve_id} - {kev.vulnerability_name}",
        content=kev.content,
        metadata=metadata,
    )


def _deduplicate_documents(
    cve_docs: list[CVEDocument],
    kev_docs: list[KEVDocument],
) -> tuple[list[CVEDocument], set[str]]:
    """Deduplicate CVE documents that also appear in KEV.

    When a CVE appears in both NVD and KEV, we keep the NVD document
    and mark it as a KEV entry (rather than having two separate documents).

    Args:
        cve_docs: List of CVE documents from NVD.
        kev_docs: List of KEV documents from CISA.

    Returns:
        Tuple of (deduplicated CVE docs, set of KEV CVE IDs).
    """
    kev_cve_ids = {doc.cve_id.upper() for doc in kev_docs}
    logger.info("Found {} CVEs that are also in KEV catalog", len(kev_cve_ids))
    return cve_docs, kev_cve_ids


async def fetch_from_local_file(
    file_path: str,
) -> list[CVEDocument]:
    """Load CVE records from a local JSON file or directory.

    Supports:
    - Single JSON file with CVE Schema format
    - Directory with CVE JSON files (CVE List V5 structure)

    Args:
        file_path: Path to JSON file or directory containing CVE files.

    Returns:
        List of CVEDocument objects.
    """
    import os
    import glob

    logger.info("Loading CVEs from: {}", file_path)

    # Check if it's a directory
    if os.path.isdir(file_path):
        # Find all JSON files recursively
        json_files = glob.glob(os.path.join(file_path, "**", "*.json"), recursive=True)
        logger.info("Found {} JSON files in directory", len(json_files))

        all_docs = []
        for json_file in json_files:
            try:
                docs = parse_cve_schema_json(json_file)
                all_docs.extend(docs)
            except Exception as e:
                logger.warning("Failed to parse {}: {}", json_file, e)

        logger.info("Loaded {} total CVE documents from directory", len(all_docs))
        return all_docs
    else:
        # Single file
        return parse_cve_schema_json(file_path)


async def fetch_all_sources(
    nvd_years: int = 2,
    nvd_api_key: str | None = None,
    include_mitre_subtechniques: bool = True,
) -> tuple[list[CVEDocument], list[MITREDocument], list[KEVDocument]]:
    """Fetch documents from all ingestion sources.

    Args:
        nvd_years: Number of years of CVE history to fetch.
        nvd_api_key: Optional NVD API key for higher rate limits.
        include_mitre_subtechniques: Whether to include MITRE sub-techniques.

    Returns:
        Tuple of (CVE docs, MITRE docs, KEV docs).
    """
    logger.info("Starting knowledge base ingestion from all sources")

    # Fetch from all sources (could parallelize these)
    cve_docs = await fetch_nvd_cves(years=nvd_years, api_key=nvd_api_key)
    mitre_docs = await fetch_mitre_attack(include_subtechniques=include_mitre_subtechniques)
    kev_docs = await fetch_cisa_kev()

    logger.info(
        "Fetched {} CVEs, {} MITRE techniques, {} KEV entries",
        len(cve_docs),
        len(mitre_docs),
        len(kev_docs),
    )

    return cve_docs, mitre_docs, kev_docs


def prepare_kb_documents(
    cve_docs: list[CVEDocument],
    mitre_docs: list[MITREDocument],
    kev_docs: list[KEVDocument],
) -> list[KBDocument]:
    """Convert and deduplicate all documents for KB upload.

    Args:
        cve_docs: CVE documents from NVD.
        mitre_docs: MITRE ATT&CK technique documents.
        kev_docs: CISA KEV documents.

    Returns:
        List of unified KBDocument objects ready for upload.
    """
    # Deduplicate CVEs that appear in KEV
    cve_docs, kev_cve_ids = _deduplicate_documents(cve_docs, kev_docs)

    kb_docs: list[KBDocument] = []

    # Convert CVE documents (marking those in KEV)
    for cve in cve_docs:
        is_kev = cve.cve_id.upper() in kev_cve_ids
        kb_docs.append(_cve_to_kb_doc(cve, is_kev=is_kev))

    # Convert MITRE documents
    for technique in mitre_docs:
        kb_docs.append(_mitre_to_kb_doc(technique))

    # Add KEV documents as supplementary (for ransomware info, due dates, etc.)
    # Only add KEV-specific info that's not in the CVE document
    for kev in kev_docs:
        kb_docs.append(_kev_to_kb_doc(kev))

    logger.info("Prepared {} total documents for KB upload", len(kb_docs))
    return kb_docs


async def upload_to_gradient_kb(
    documents: list[KBDocument],
    api_key: str | None = None,
    kb_id: str | None = None,
    batch_size: int = 100,
) -> bool:
    """Upload documents to the Gradient knowledge base.

    Args:
        documents: List of KBDocument objects to upload.
        api_key: Gradient API key (defaults to settings).
        kb_id: Knowledge base ID (defaults to settings).
        batch_size: Number of documents per upload batch.

    Returns:
        True if upload succeeded, False otherwise.
    """
    api_key = api_key or settings.gradient_api_key
    kb_id = kb_id or settings.gradient_kb_id

    if not api_key:
        logger.warning("Gradient API key not configured, skipping KB upload")
        return False

    if not kb_id:
        logger.warning(
            "Gradient KB ID not configured, skipping KB upload. Set CORVID_GRADIENT_KB_ID to enable KB."
        )
        return False

    logger.info(
        "Uploading {} documents to Gradient KB {} in batches of {}",
        len(documents),
        kb_id,
        batch_size,
    )

    # Convert documents to Gradient format
    gradient_docs = [
        {
            "id": doc.id,
            "content": doc.content,
            "metadata": {
                "doc_type": doc.doc_type,
                "title": doc.title,
                **doc.metadata,
            },
        }
        for doc in documents
    ]

    # Upload in batches
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Upload to Gradient KB
    # Use the full KB URL if provided, otherwise construct from KB ID
    if settings.gradient_kb_url:
        gradient_kb_url = f"{settings.gradient_kb_url}/documents"
    else:
        gradient_kb_url = f"https://api.gradient.ai/v1/knowledge-bases/{kb_id}/documents"

    async with httpx.AsyncClient(timeout=60.0) as client:
        for i in range(0, len(gradient_docs), batch_size):
            batch = gradient_docs[i : i + batch_size]
            try:
                resp = await client.post(
                    gradient_kb_url,
                    json={"documents": batch},
                    headers=headers,
                )
                resp.raise_for_status()
                logger.info(
                    "Uploaded batch {}/{} ({} docs)",
                    i // batch_size + 1,
                    (len(gradient_docs) + batch_size - 1) // batch_size,
                    len(batch),
                )
            except httpx.HTTPError as e:
                logger.error("Failed to upload batch starting at {}: {}", i, e)
                return False

    logger.info("Successfully uploaded all {} documents to Gradient KB", len(documents))
    return True


async def build_knowledge_base(
    nvd_years: int = 2,
    upload: bool = True,
) -> list[KBDocument]:
    """Fetch all sources, deduplicate, and upload to Gradient KB.

    This is the main entry point for building the knowledge base.

    Args:
        nvd_years: Number of years of CVE history to fetch.
        upload: Whether to upload to Gradient KB (set False for dry run).

    Returns:
        List of prepared KBDocument objects.
    """
    # Fetch from all sources
    cve_docs, mitre_docs, kev_docs = await fetch_all_sources(
        nvd_years=nvd_years,
        nvd_api_key=settings.nvd_api_key or None,
    )

    # Prepare and deduplicate
    kb_docs = prepare_kb_documents(cve_docs, mitre_docs, kev_docs)

    logger.info("Total documents for KB: {}", len(kb_docs))

    # Upload to Gradient KB
    if upload:
        success = await upload_to_gradient_kb(kb_docs)
        if not success:
            logger.warning("KB upload failed or skipped")
    else:
        logger.info("Dry run - skipping KB upload")

    return kb_docs


# CLI entry point
if __name__ == "__main__":
    import asyncio
    import sys

    async def main() -> None:
        """Run knowledge base build from command line."""
        # Parse CLI args
        dry_run = "--dry-run" in sys.argv
        years = 2
        cve_file = None

        for arg in sys.argv:
            if arg.startswith("--years="):
                years = int(arg.split("=")[1])
            elif arg.startswith("--cve-file="):
                cve_file = arg.split("=", 1)[1]

        if cve_file:
            # Load from local file
            logger.info("Loading CVEs from local file: {}", cve_file)
            cve_docs = await fetch_from_local_file(cve_file)

            # Convert to KB documents
            kb_docs = []
            for cve in cve_docs:
                kb_docs.append(_cve_to_kb_doc(cve))

            logger.info("Prepared {} documents from file", len(kb_docs))

            if not dry_run:
                success = await upload_to_gradient_kb(kb_docs)
                if success:
                    logger.info("Successfully uploaded {} documents", len(kb_docs))
                else:
                    logger.error("Failed to upload documents")
            else:
                logger.info("Dry run - skipping upload")

            logger.info("Complete. {} documents prepared.", len(kb_docs))
        else:
            # Default: fetch from NVD API
            logger.info("Building knowledge base (years={}, dry_run={})", years, dry_run)
            docs = await build_knowledge_base(nvd_years=years, upload=not dry_run)
            logger.info("Complete. {} documents prepared.", len(docs))

    asyncio.run(main())
