"""Tests for IOC normalization, validation, and type detection."""

import pytest

from corvid.worker.normalizer import IOCType, detect_ioc_type, normalize_ioc, validate_ioc


class TestNormalizeIOC:
    """Tests for the normalize_ioc function."""

    def test_strips_whitespace(self) -> None:
        assert normalize_ioc("  10.0.0.1  ") == "10.0.0.1"

    def test_lowercases(self) -> None:
        assert normalize_ioc("EVIL.EXAMPLE.COM") == "evil.example.com"

    def test_refangs_hxxp(self) -> None:
        assert normalize_ioc("hxxps://evil.com/payload") == "https://evil.com/payload"

    def test_refangs_brackets(self) -> None:
        assert normalize_ioc("evil[.]example[.]com") == "evil.example.com"

    def test_refangs_email(self) -> None:
        assert normalize_ioc("attacker[@]evil[.]com") == "attacker@evil.com"

    def test_combined_defanging(self) -> None:
        assert normalize_ioc("hxxp://evil[.]com/bad") == "http://evil.com/bad"

    def test_already_clean(self) -> None:
        assert normalize_ioc("10.0.0.1") == "10.0.0.1"

    def test_empty_string(self) -> None:
        assert normalize_ioc("") == ""

    def test_hash_unchanged(self) -> None:
        h = "d41d8cd98f00b204e9800998ecf8427e"
        assert normalize_ioc(h) == h


class TestValidateIOC:
    """Tests for the validate_ioc function."""

    # --- IP addresses ---
    def test_valid_ipv4(self) -> None:
        assert validate_ioc(IOCType.IP, "192.168.1.1") is True

    def test_valid_ipv6(self) -> None:
        assert validate_ioc(IOCType.IP, "::1") is True

    def test_valid_ipv6_full(self) -> None:
        assert validate_ioc(IOCType.IP, "2001:db8::1") is True

    def test_invalid_ip(self) -> None:
        assert validate_ioc(IOCType.IP, "999.999.999.999") is False

    def test_invalid_ip_text(self) -> None:
        assert validate_ioc(IOCType.IP, "not_an_ip") is False

    # --- Hashes ---
    def test_valid_md5(self) -> None:
        assert validate_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e") is True

    def test_invalid_md5_too_short(self) -> None:
        assert validate_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204") is False

    def test_valid_sha1(self) -> None:
        assert (
            validate_ioc(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
            is True
        )

    def test_valid_sha256(self) -> None:
        assert validate_ioc(IOCType.HASH_SHA256, "a" * 64) is True

    def test_invalid_sha256_wrong_chars(self) -> None:
        assert validate_ioc(IOCType.HASH_SHA256, "g" * 64) is False

    # --- Domains ---
    def test_valid_domain(self) -> None:
        assert validate_ioc(IOCType.DOMAIN, "evil.example.com") is True

    def test_valid_short_domain(self) -> None:
        assert validate_ioc(IOCType.DOMAIN, "evil.co") is True

    def test_invalid_domain_leading_dash(self) -> None:
        assert validate_ioc(IOCType.DOMAIN, "-evil.com") is False

    # --- URLs ---
    def test_valid_http_url(self) -> None:
        assert validate_ioc(IOCType.URL, "http://evil.com/payload.exe") is True

    def test_valid_https_url(self) -> None:
        assert validate_ioc(IOCType.URL, "https://evil.com/payload") is True

    def test_invalid_url_no_scheme(self) -> None:
        assert validate_ioc(IOCType.URL, "evil.com/payload") is False

    # --- Email ---
    def test_valid_email(self) -> None:
        assert validate_ioc(IOCType.EMAIL, "attacker@evil.com") is True

    def test_invalid_email_no_at(self) -> None:
        assert validate_ioc(IOCType.EMAIL, "attacker.evil.com") is False


class TestDetectIOCType:
    """Tests for the detect_ioc_type function."""

    def test_detect_ipv4(self) -> None:
        assert detect_ioc_type("192.168.1.1") == IOCType.IP

    def test_detect_ipv6(self) -> None:
        assert detect_ioc_type("2001:db8::1") == IOCType.IP

    def test_detect_md5(self) -> None:
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH_MD5

    def test_detect_sha1(self) -> None:
        assert (
            detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.HASH_SHA1
        )

    def test_detect_sha256(self) -> None:
        assert detect_ioc_type("a" * 64) == IOCType.HASH_SHA256

    def test_detect_url(self) -> None:
        assert detect_ioc_type("https://evil.com/payload") == IOCType.URL

    def test_detect_email(self) -> None:
        assert detect_ioc_type("bad@evil.com") == IOCType.EMAIL

    def test_detect_domain(self) -> None:
        assert detect_ioc_type("evil.example.com") == IOCType.DOMAIN

    def test_detect_defanged_url(self) -> None:
        assert detect_ioc_type("hxxps://evil[.]com/payload") == IOCType.URL

    def test_detect_unknown(self) -> None:
        assert detect_ioc_type("!!!not_an_ioc!!!") is None

    def test_detect_normalizes_first(self) -> None:
        assert detect_ioc_type("  192.168.1.1  ") == IOCType.IP

    def test_detect_uppercase_hash(self) -> None:
        assert detect_ioc_type("D41D8CD98F00B204E9800998ECF8427E") == IOCType.HASH_MD5
