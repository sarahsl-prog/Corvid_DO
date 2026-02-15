#!/usr/bin/env python3
"""Create test data for Corvid testing.

This script creates various test IOCs and analysis requests
to help with manual testing of the platform.

Usage:
    python tests/scripts/create_test_data.py [--url URL] [--clean]
"""

import argparse
import asyncio
import sys
from typing import Any

import httpx


TEST_IOCS = [
    {"type": "ip", "value": "8.8.8.8", "tags": ["test", "benign", "public-dns"]},
    {"type": "ip", "value": "1.1.1.1", "tags": ["test", "benign", "public-dns"]},
    {"type": "ip", "value": "185.234.219.31", "tags": ["test", "malicious"]},
    {"type": "ip", "value": "192.168.1.1", "tags": ["test", "private-ip"]},
    {"type": "ip", "value": "10.0.0.1", "tags": ["test", "private-ip"]},
    {"type": "ip", "value": "127.0.0.1", "tags": ["test", "localhost"]},
    {"type": "domain", "value": "example.com", "tags": ["test", "benign"]},
    {"type": "domain", "value": "google.com", "tags": ["test", "benign"]},
    {"type": "domain", "value": "evil.com", "tags": ["test", "malicious"]},
    {"type": "domain", "value": "malware.com", "tags": ["test", "malicious"]},
    {"type": "url", "value": "https://example.com/malware.exe", "tags": ["test", "malicious-url"]},
    {"type": "url", "value": "https://google.com", "tags": ["test", "benign-url"]},
    {"type": "url", "value": "http://evil.com/payload.exe", "tags": ["test", "malicious-url"]},
    {
        "type": "hash_md5",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "tags": ["test", "hash", "md5"],
    },
    {
        "type": "hash_sha1",
        "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "tags": ["test", "hash", "sha1"],
    },
    {
        "type": "hash_sha256",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "tags": ["test", "hash", "sha256"],
    },
    {"type": "email", "value": "security@google.com", "tags": ["test", "benign-email"]},
    {"type": "email", "value": "attacker@evil.com", "tags": ["test", "malicious-email"]},
]

ANALYSIS_REQUESTS = [
    {
        "iocs": [{"type": "ip", "value": "8.8.8.8"}],
        "context": "Testing benign DNS server",
        "priority": "low",
    },
    {
        "iocs": [{"type": "ip", "value": "185.234.219.31"}],
        "context": "Testing known malicious IP",
        "priority": "high",
    },
    {
        "iocs": [{"type": "domain", "value": "example.com"}],
        "context": "Testing benign domain",
        "priority": "low",
    },
    {
        "iocs": [{"type": "url", "value": "https://evil.com/malware.exe"}],
        "context": "Testing malicious URL",
        "priority": "high",
    },
    {
        "iocs": [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "185.234.219.31"},
            {"type": "domain", "value": "example.com"},
        ],
        "context": "Batch analysis test",
        "priority": "medium",
    },
]


async def create_ioc(client: httpx.AsyncClient, base_url: str, ioc: dict) -> dict | None:
    """Create a single IOC."""
    try:
        response = await client.post(
            f"{base_url}/api/v1/iocs/",
            json=ioc,
            timeout=30.0,
        )
        if response.status_code == 201:
            return response.json()
        else:
            print(f"  ❌ Failed to create {ioc['type']}:{ioc['value']} - {response.status_code}")
            return None
    except Exception as e:
        print(f"  ❌ Error creating {ioc['type']}:{ioc['value']} - {e}")
        return None


async def run_analysis(client: httpx.AsyncClient, base_url: str, request: dict) -> dict | None:
    """Run an analysis request."""
    try:
        response = await client.post(
            f"{base_url}/api/v1/iocs/analyze",
            json=request,
            timeout=120.0,
        )
        if response.status_code in (200, 201):
            return response.json()
        else:
            print(f"  ❌ Analysis failed - {response.status_code}: {response.text[:100]}")
            return None
    except Exception as e:
        print(f"  ❌ Analysis error - {e}")
        return None


async def cleanup_test_data(base_url: str) -> None:
    """Delete test IOCs."""
    print("\n🧹 Cleaning up test data...")
    async with httpx.AsyncClient() as client:
        try:
            # Get all IOCs with test tag
            response = await client.get(f"{base_url}/api/v1/iocs?tag=test", timeout=10.0)
            if response.status_code == 200:
                iocs = response.json()
                for ioc in iocs.get("items", []):
                    await client.delete(f"{base_url}/api/v1/iocs/{ioc['id']}", timeout=10.0)
                print(f"  Deleted {len(iocs.get('items', []))} test IOCs")
        except Exception as e:
            print(f"  Cleanup error: {e}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Create test data for Corvid")
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the Corvid API",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean up test data before creating new",
    )
    parser.add_argument(
        "--ioc-only",
        action="store_true",
        help="Only create IOCs, skip analysis",
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="Only run analysis, skip creating IOCs",
    )
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print(f"📡 Testing against: {base_url}")

    # Check health
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{base_url}/health", timeout=5.0)
            if response.status_code != 200:
                print(f"❌ API not healthy: {response.status_code}")
                sys.exit(1)
            print("✅ API is healthy")
        except Exception as e:
            print(f"❌ Cannot connect to API: {e}")
            sys.exit(1)

    if args.clean:
        await cleanup_test_data(base_url)

    if not args.analysis_only:
        print("\n📝 Creating test IOCs...")
        created_count = 0
        async with httpx.AsyncClient() as client:
            tasks = [create_ioc(client, base_url, ioc) for ioc in TEST_IOCS]
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    created_count += 1
                    ioc = result
                    print(f"  ✅ Created {ioc['type']}:{ioc['value']} (ID: {ioc['id']})")

        print(f"\n📊 Created {created_count}/{len(TEST_IOCS)} test IOCs")

    if not args.ioc_only:
        print("\n🔍 Running analysis tests...")
        async with httpx.AsyncClient() as client:
            for i, request in enumerate(ANALYSIS_REQUESTS, 1):
                print(f"\n  Test {i}/{len(ANALYSIS_REQUESTS)}: {request['context']}")
                result = await run_analysis(client, base_url, request)
                if result:
                    analysis_id = result.get("analysis_id", "N/A")
                    status = result.get("status", "N/A")
                    print(f"    ✅ Analysis started - ID: {analysis_id}, Status: {status}")

    print("\n✨ Test data creation complete!")


if __name__ == "__main__":
    asyncio.run(main())
