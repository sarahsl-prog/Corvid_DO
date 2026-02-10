"""MITRE ATT&CK ingestion module for knowledge base population.

Fetches MITRE ATT&CK data from the official STIX 2.1 JSON bundle
and formats techniques as documents for the Gradient knowledge base.

Scope: All Enterprise ATT&CK techniques (~700 documents).
"""

from dataclasses import dataclass, field

import httpx
from loguru import logger

# Official MITRE ATT&CK STIX bundle URLs
MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


@dataclass
class MITREDocument:
    """A MITRE ATT&CK technique document for knowledge base ingestion."""

    technique_id: str  # "T1071.001"
    name: str  # "Application Layer Protocol: Web Protocols"
    description: str
    tactics: list[str] = field(default_factory=list)  # ["command-and-control"]
    platforms: list[str] = field(default_factory=list)  # ["Windows", "Linux", "macOS"]
    data_sources: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""  # Link to MITRE ATT&CK page
    content: str = ""  # Full text for embedding

    def __post_init__(self) -> None:
        """Generate the content field from other fields."""
        if not self.content:
            self.content = self._build_content()

    def _build_content(self) -> str:
        """Build searchable content text from all fields."""
        parts = [
            f"MITRE ATT&CK Technique: {self.technique_id}",
            f"Name: {self.name}",
        ]
        if self.tactics:
            parts.append(f"Tactics: {', '.join(self.tactics)}")
        if self.platforms:
            parts.append(f"Platforms: {', '.join(self.platforms)}")
        parts.append(f"Description: {self.description}")
        if self.data_sources:
            parts.append(f"Data Sources: {', '.join(self.data_sources)}")
        if self.detection:
            parts.append(f"Detection: {self.detection}")
        if self.mitigations:
            parts.append(f"Mitigations: {', '.join(self.mitigations)}")
        if self.url:
            parts.append(f"Reference: {self.url}")
        return "\n".join(parts)


def _extract_external_id(stix_object: dict) -> str | None:
    """Extract the MITRE ATT&CK technique ID from external references.

    Args:
        stix_object: A STIX object from the bundle.

    Returns:
        The technique ID (e.g., "T1071.001") or None if not found.
    """
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_url(stix_object: dict) -> str:
    """Extract the MITRE ATT&CK URL from external references.

    Args:
        stix_object: A STIX object from the bundle.

    Returns:
        The ATT&CK URL or empty string.
    """
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _extract_tactics(stix_object: dict, tactic_map: dict[str, str]) -> list[str]:
    """Extract tactic names from kill chain phases.

    Args:
        stix_object: A STIX object from the bundle.
        tactic_map: Mapping of phase names to tactic display names.

    Returns:
        List of tactic names.
    """
    tactics = []
    for phase in stix_object.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            phase_name = phase.get("phase_name", "")
            if phase_name in tactic_map:
                tactics.append(tactic_map[phase_name])
            else:
                tactics.append(phase_name.replace("-", " ").title())
    return tactics


def _build_tactic_map(stix_objects: list[dict]) -> dict[str, str]:
    """Build a mapping of tactic short names to display names.

    Args:
        stix_objects: All STIX objects from the bundle.

    Returns:
        Dict mapping phase names to tactic display names.
    """
    tactic_map = {}
    for obj in stix_objects:
        if obj.get("type") == "x-mitre-tactic":
            short_name = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            if short_name and name:
                tactic_map[short_name] = name
    return tactic_map


def _build_mitigation_map(
    stix_objects: list[dict], relationships: list[dict]
) -> dict[str, list[str]]:
    """Build a mapping of technique IDs to their mitigations.

    Args:
        stix_objects: All STIX objects from the bundle.
        relationships: All relationship objects from the bundle.

    Returns:
        Dict mapping technique STIX IDs to lists of mitigation names.
    """
    # Map mitigation STIX IDs to names
    mitigation_names: dict[str, str] = {}
    for obj in stix_objects:
        if obj.get("type") == "course-of-action":
            mitigation_names[obj["id"]] = obj.get("name", "")

    # Find relationships: mitigation -> mitigates -> technique
    technique_mitigations: dict[str, list[str]] = {}
    for rel in relationships:
        if rel.get("relationship_type") == "mitigates":
            source_id = rel.get("source_ref", "")
            target_id = rel.get("target_ref", "")
            if source_id in mitigation_names and target_id:
                if target_id not in technique_mitigations:
                    technique_mitigations[target_id] = []
                technique_mitigations[target_id].append(mitigation_names[source_id])

    return technique_mitigations


def _parse_technique(
    stix_object: dict,
    tactic_map: dict[str, str],
    mitigation_map: dict[str, list[str]],
) -> MITREDocument | None:
    """Parse a STIX attack-pattern object into a MITREDocument.

    Args:
        stix_object: A STIX attack-pattern object.
        tactic_map: Mapping of phase names to tactic display names.
        mitigation_map: Mapping of technique STIX IDs to mitigation names.

    Returns:
        MITREDocument if parsing succeeds, None otherwise.
    """
    if stix_object.get("type") != "attack-pattern":
        return None

    # Skip revoked or deprecated techniques
    if stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"):
        return None

    technique_id = _extract_external_id(stix_object)
    if not technique_id:
        return None

    name = stix_object.get("name", "")
    if not name:
        return None

    description = stix_object.get("description", "")
    # Clean up markdown/formatting
    description = description.replace("\n\n", " ").replace("\n", " ")

    tactics = _extract_tactics(stix_object, tactic_map)
    platforms = stix_object.get("x_mitre_platforms", [])
    data_sources = stix_object.get("x_mitre_data_sources", [])
    detection = stix_object.get("x_mitre_detection", "")
    if detection:
        detection = detection.replace("\n\n", " ").replace("\n", " ")

    url = _extract_url(stix_object)
    mitigations = mitigation_map.get(stix_object["id"], [])

    return MITREDocument(
        technique_id=technique_id,
        name=name,
        description=description[:2000],  # Limit description length
        tactics=tactics,
        platforms=platforms,
        data_sources=data_sources[:10],  # Limit data sources
        mitigations=mitigations[:10],  # Limit mitigations
        detection=detection[:1000] if detection else "",
        url=url,
    )


async def fetch_mitre_attack(
    include_subtechniques: bool = True,
) -> list[MITREDocument]:
    """Fetch MITRE ATT&CK Enterprise techniques from the official STIX bundle.

    Args:
        include_subtechniques: Whether to include sub-techniques (T1234.001).

    Returns:
        List of MITREDocument objects ready for knowledge base upload.
    """
    logger.info("Fetching MITRE ATT&CK Enterprise STIX bundle")

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.get(MITRE_ENTERPRISE_URL)
            resp.raise_for_status()
            bundle = resp.json()
        except httpx.HTTPError as e:
            logger.error("Failed to fetch MITRE ATT&CK bundle: {}", e)
            return []

    stix_objects = bundle.get("objects", [])
    logger.info("Loaded STIX bundle with {} objects", len(stix_objects))

    # Separate relationships from other objects
    relationships = [obj for obj in stix_objects if obj.get("type") == "relationship"]
    other_objects = [obj for obj in stix_objects if obj.get("type") != "relationship"]

    # Build lookup maps
    tactic_map = _build_tactic_map(other_objects)
    mitigation_map = _build_mitigation_map(other_objects, relationships)

    # Parse techniques
    documents: list[MITREDocument] = []
    for obj in other_objects:
        if obj.get("type") != "attack-pattern":
            continue

        doc = _parse_technique(obj, tactic_map, mitigation_map)
        if doc:
            # Filter sub-techniques if not wanted
            if not include_subtechniques and "." in doc.technique_id:
                continue
            documents.append(doc)

    # Sort by technique ID for consistent ordering
    documents.sort(key=lambda d: d.technique_id)

    logger.info("MITRE ATT&CK ingestion complete: {} technique documents", len(documents))
    return documents


async def fetch_technique_by_id(technique_id: str) -> MITREDocument | None:
    """Fetch a single MITRE ATT&CK technique by its ID.

    Note: This fetches the entire bundle and filters. For repeated lookups,
    consider caching the full bundle locally.

    Args:
        technique_id: The technique ID (e.g., "T1071.001").

    Returns:
        MITREDocument if found, None otherwise.
    """
    documents = await fetch_mitre_attack(include_subtechniques=True)
    for doc in documents:
        if doc.technique_id == technique_id:
            return doc
    return None
