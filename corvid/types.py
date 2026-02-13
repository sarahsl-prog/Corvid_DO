"""Shared type definitions for Corvid.

This module contains types that are used across multiple modules
to avoid duplication and ensure consistency.
"""

import enum


class IOCType(str, enum.Enum):
    """Supported IOC (Indicator of Compromise) types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
