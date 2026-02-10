"""IOC normalization, validation, and auto-type-detection.

Handles defanging reversal (hxxp -> http, [.] -> .), format validation
via regex and ipaddress, and automatic IOC type detection from raw values.
"""

import ipaddress
import re
from enum import Enum

from loguru import logger


class IOCType(str, Enum):
    """Supported IOC (Indicator of Compromise) types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


# Compiled regex patterns for IOC format validation
PATTERNS: dict[IOCType, re.Pattern[str]] = {
    IOCType.HASH_MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.HASH_SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.HASH_SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
    IOCType.DOMAIN: re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    ),
    IOCType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    IOCType.URL: re.compile(r"^https?://\S+$"),
}


def normalize_ioc(value: str) -> str:
    """Normalize an IOC value: strip whitespace, lowercase, re-fang.

    Common defanging formats are reversed:
      - hxxp -> http, hxxps -> https
      - [.] -> .
      - [@] -> @

    Args:
        value: Raw IOC string from user input.

    Returns:
        Cleaned, lowercased IOC string.
    """
    value = value.strip()
    # Re-fang common defanged formats
    value = value.replace("hxxp", "http").replace("[.]", ".").replace("[@]", "@")
    # Lowercase for consistency (hashes, domains are case-insensitive)
    value = value.lower()
    return value


def validate_ioc(ioc_type: IOCType, value: str) -> bool:
    """Validate that a value matches the expected format for its IOC type.

    Args:
        ioc_type: The declared IOC type.
        value: The IOC value to validate (should already be normalized).

    Returns:
        True if the value matches the expected format.
    """
    if ioc_type == IOCType.IP:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    pattern = PATTERNS.get(ioc_type)
    if pattern:
        return bool(pattern.match(value))

    logger.warning("No validation pattern for IOC type: {}", ioc_type)
    return False


def detect_ioc_type(value: str) -> IOCType | None:
    """Auto-detect the IOC type from a raw value.

    Detection order matters: IP is checked first (most specific), then hashes
    by length, then URLs (before domains since URLs contain domains), then
    email (before domains), and finally domain as the most permissive match.

    Args:
        value: Raw IOC string (will be normalized first).

    Returns:
        The detected IOCType, or None if no type could be determined.
    """
    value = normalize_ioc(value)

    # Try IP first (most specific)
    try:
        ipaddress.ip_address(value)
        return IOCType.IP
    except ValueError:
        pass

    # Hashes by length (deterministic, non-overlapping)
    if PATTERNS[IOCType.HASH_MD5].match(value):
        return IOCType.HASH_MD5
    if PATTERNS[IOCType.HASH_SHA1].match(value):
        return IOCType.HASH_SHA1
    if PATTERNS[IOCType.HASH_SHA256].match(value):
        return IOCType.HASH_SHA256

    # URL before domain (URLs contain domains)
    if PATTERNS[IOCType.URL].match(value):
        return IOCType.URL

    # Email before domain
    if PATTERNS[IOCType.EMAIL].match(value):
        return IOCType.EMAIL

    # Domain last (most permissive text pattern)
    if PATTERNS[IOCType.DOMAIN].match(value):
        return IOCType.DOMAIN

    logger.debug("Could not detect IOC type for value: {}", value)
    return None
