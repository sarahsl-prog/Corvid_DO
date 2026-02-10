"""Base enrichment provider interface.

All external threat intelligence integrations implement BaseEnrichmentProvider,
which defines a consistent interface for enriching IOCs from different sources.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentResult:
    """Result from an enrichment provider lookup.

    Attributes:
        source: Name of the enrichment provider (e.g. "abuseipdb").
        raw_response: Full API response data for storage.
        summary: Human-readable one-line summary of findings.
        success: Whether the lookup completed successfully.
        error: Error message if the lookup failed.
    """

    source: str
    raw_response: dict[str, Any]
    summary: str
    success: bool
    error: str | None = field(default=None)


class BaseEnrichmentProvider(ABC):
    """Abstract base class for all enrichment providers.

    Each provider must declare which IOC types it supports and implement
    the enrich() method for performing the actual API lookup.
    """

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique identifier for this provider (e.g. 'abuseipdb')."""
        ...

    @property
    @abstractmethod
    def supported_types(self) -> list[str]:
        """List of IOC type strings this provider can enrich."""
        ...

    @abstractmethod
    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Perform an enrichment lookup for the given IOC.

        Args:
            ioc_type: The IOC type (e.g. 'ip', 'domain', 'hash_sha256').
            ioc_value: The normalized IOC value.

        Returns:
            EnrichmentResult with the lookup outcome.
        """
        ...

    def supports(self, ioc_type: str) -> bool:
        """Check if this provider supports the given IOC type."""
        return ioc_type in self.supported_types
