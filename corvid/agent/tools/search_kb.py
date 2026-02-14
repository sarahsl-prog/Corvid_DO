"""Agent tool for semantic search over the Gradient knowledge base.

Searches CVE advisories, MITRE ATT&CK techniques, and CISA KEV entries
using the Gradient KB API.
"""

from typing import Any

import httpx
from loguru import logger

from corvid.config import settings


async def search_knowledge_base(
    query: str,
    top_k: int = 5,
    doc_types: list[str] | None = None,
) -> dict[str, Any]:
    """Semantic search over the Gradient knowledge base.

    Searches CVE advisories, MITRE ATT&CK techniques, and CISA KEV entries.

    Args:
        query: The search query (natural language or keywords).
        top_k: Number of top results to return.
        doc_types: Optional filter by document type ("cve", "mitre_technique", "kev").

    Returns:
        Dict containing:
        - documents: List of matching documents with content, metadata, score
        - total_found: Number of documents returned
        - message: Human-readable status
    """
    logger.debug("KB search: '{}' (top_k={}, types={})", query, top_k, doc_types)

    if not settings.gradient_api_key or not settings.gradient_kb_id:
        logger.warning("Gradient KB not configured, returning empty results")
        return {
            "documents": [],
            "total_found": 0,
            "message": "Knowledge base not configured. Set CORVID_GRADIENT_API_KEY "
            "and CORVID_GRADIENT_KB_ID environment variables.",
        }

    # Build request to Gradient KB search API
    if settings.gradient_kb_url:
        gradient_search_url = f"{settings.gradient_kb_url}/search"
    else:
        gradient_search_url = (
            f"https://api.gradient.ai/v1/knowledge-bases/{settings.gradient_kb_id}/search"
        )

    headers = {
        "Authorization": f"Bearer {settings.gradient_api_key}",
        "Content-Type": "application/json",
    }

    request_body: dict[str, Any] = {
        "query": query,
        "top_k": top_k,
    }

    # Add document type filter if specified
    if doc_types:
        request_body["filters"] = {"doc_type": {"$in": doc_types}}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                gradient_search_url,
                json=request_body,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            documents = []
            for result in data.get("results", []):
                doc = {
                    "id": result.get("id", ""),
                    "title": result.get("metadata", {}).get("title", ""),
                    "content_snippet": _truncate_content(result.get("content", ""), 500),
                    "doc_type": result.get("metadata", {}).get("doc_type", "unknown"),
                    "relevance_score": result.get("score", 0.0),
                    "metadata": result.get("metadata", {}),
                }
                documents.append(doc)

            total_found = len(documents)

            if total_found > 0:
                # Summarize what was found
                type_counts: dict[str, int] = {}
                for doc in documents:
                    dt = doc["doc_type"]
                    type_counts[dt] = type_counts.get(dt, 0) + 1

                type_summary = ", ".join(f"{count} {dtype}" for dtype, count in type_counts.items())
                message = f"Found {total_found} relevant document(s): {type_summary}."
            else:
                message = f"No documents found matching '{query}'."

            logger.info("KB search '{}': {} results", query, total_found)

            return {
                "documents": documents,
                "total_found": total_found,
                "message": message,
            }

    except httpx.HTTPError as e:
        logger.error("Gradient KB search failed: {}", e)
        return {
            "documents": [],
            "total_found": 0,
            "message": f"Knowledge base search failed: {e}",
        }


def _truncate_content(content: str, max_length: int) -> str:
    """Truncate content to max length, adding ellipsis if needed."""
    if len(content) <= max_length:
        return content
    return content[: max_length - 3] + "..."


async def search_mitre_techniques(
    query: str,
    top_k: int = 5,
) -> dict[str, Any]:
    """Search specifically for MITRE ATT&CK techniques.

    Convenience wrapper around search_knowledge_base.

    Args:
        query: Search query (technique name, tactic, or description).
        top_k: Number of results to return.

    Returns:
        KB search results filtered to MITRE techniques only.
    """
    return await search_knowledge_base(query, top_k, doc_types=["mitre_technique"])


async def search_cve_advisories(
    query: str,
    top_k: int = 5,
    include_kev: bool = True,
) -> dict[str, Any]:
    """Search for CVE advisories and optionally KEV entries.

    Convenience wrapper around search_knowledge_base.

    Args:
        query: Search query (CVE ID, product, or description).
        top_k: Number of results to return.
        include_kev: Whether to include CISA KEV entries.

    Returns:
        KB search results filtered to CVE/KEV documents.
    """
    doc_types = ["cve"]
    if include_kev:
        doc_types.append("kev")
    return await search_knowledge_base(query, top_k, doc_types=doc_types)


async def get_kev_status(cve_id: str) -> dict[str, Any]:
    """Check if a CVE is in the CISA KEV catalog.

    Args:
        cve_id: The CVE ID to check (e.g., "CVE-2024-21762").

    Returns:
        Dict with is_kev status and KEV document if found.
    """
    # Search for exact CVE ID in KEV documents
    results = await search_knowledge_base(
        cve_id,
        top_k=1,
        doc_types=["kev"],
    )

    if results["documents"]:
        doc = results["documents"][0]
        # Verify it's an exact match
        if cve_id.upper() in doc.get("id", "").upper():
            return {
                "is_kev": True,
                "cve_id": cve_id,
                "kev_document": doc,
                "message": f"{cve_id} IS in the CISA Known Exploited Vulnerabilities catalog. "
                "This vulnerability is actively exploited in the wild.",
            }

    return {
        "is_kev": False,
        "cve_id": cve_id,
        "kev_document": None,
        "message": f"{cve_id} is NOT in the CISA KEV catalog.",
    }


# Tool schema for Gradient agent registration
SEARCH_KB_SCHEMA = {
    "name": "search_knowledge_base",
    "description": "Search the security knowledge base for relevant CVE advisories, "
    "MITRE ATT&CK techniques, and CISA KEV (Known Exploited Vulnerabilities) entries. "
    "Use semantic/natural language queries to find relevant security information.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query - can be keywords, CVE IDs, technique names, "
                "or natural language like 'remote code execution in web servers'",
            },
            "top_k": {
                "type": "integer",
                "description": "Number of top results to return (default: 5)",
                "default": 5,
            },
            "doc_types": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["cve", "mitre_technique", "kev"],
                },
                "description": "Optional filter by document type",
            },
        },
        "required": ["query"],
    },
}
