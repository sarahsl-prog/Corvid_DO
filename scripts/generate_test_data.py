#!/usr/bin/env python3
"""
generate_test_data.py - Generate test data for Corvid API testing

Usage:
    python scripts/generate_test_data.py [--url URL] [--count N] [--type TYPE]

Options:
    --url URL     Target URL (default: http://localhost:8000)
    --count N     Number of IOCs to create (default: 50)
    --type TYPE   IOC type to create: ip, domain, hash, url, or mixed (default: mixed)

This script creates realistic test IOCs for manual testing and demos.
"""

import argparse
import random
import sys

import httpx

# Sample realistic-looking test data (using documentation/test ranges)
TEST_IPS = [
    # RFC 5737 documentation blocks
    "192.0.2.1", "192.0.2.50", "192.0.2.100", "192.0.2.200",
    "198.51.100.1", "198.51.100.50", "198.51.100.100", "198.51.100.200",
    "203.0.113.1", "203.0.113.50", "203.0.113.100", "203.0.113.200",
    # Private ranges for testing
    "10.0.0.1", "10.0.0.50", "10.1.1.1", "10.255.255.1",
    "172.16.0.1", "172.16.0.50", "172.31.255.1",
    "192.168.1.1", "192.168.1.100", "192.168.10.1",
]

TEST_DOMAINS = [
    # .example reserved for testing (RFC 2606)
    "malware.example.com",
    "c2.example.com",
    "phishing.example.com",
    "evil-server.example.net",
    "botnet-controller.example.org",
    "suspicious-domain.example.com",
    "data-exfil.example.net",
    "ransomware-payment.example.com",
    "credential-harvester.example.org",
    "backdoor-server.example.net",
    # Subdomains
    "api.malware.example.com",
    "cdn.evil.example.com",
    "update.suspicious.example.net",
]

# Common tags for threat intelligence
TAGS = [
    "malware", "c2", "botnet", "phishing", "ransomware",
    "apt", "trojan", "backdoor", "exploit", "scanner",
    "spam", "dga", "tor-exit", "vpn", "proxy",
    "suspicious", "high-priority", "needs-review",
]

# Threat actor tags
THREAT_ACTORS = [
    "apt28", "apt29", "lazarus", "fin7", "cobalt-group",
]

# Campaign tags
CAMPAIGNS = [
    "campaign-alpha", "operation-sunrise", "dark-phoenix",
]


def generate_ip_ioc() -> dict:
    """Generate a random IP IOC."""
    return {
        "type": "ip",
        "value": random.choice(TEST_IPS) + f".{random.randint(1, 254)}",
        "tags": random.sample(TAGS, random.randint(1, 3)),
    }


def generate_domain_ioc() -> dict:
    """Generate a random domain IOC."""
    domain = random.choice(TEST_DOMAINS)
    # Sometimes add a random subdomain
    if random.random() > 0.5:
        prefix = random.choice(["www", "api", "cdn", "update", "ns1"])
        domain = f"{prefix}.{domain}"

    return {
        "type": "domain",
        "value": domain,
        "tags": random.sample(TAGS, random.randint(1, 3)),
    }


def generate_hash_ioc() -> dict:
    """Generate a random hash IOC."""
    hash_type = random.choice(["hash_sha256", "hash_md5", "hash_sha1"])

    if hash_type == "hash_sha256":
        length = 64
    elif hash_type == "hash_sha1":
        length = 40
    else:
        length = 32

    value = "".join(random.choices("0123456789abcdef", k=length))

    tags = random.sample(TAGS, random.randint(1, 3))
    # Add file-related tags
    if random.random() > 0.5:
        tags.append(random.choice(["executable", "document", "script", "archive"]))

    return {
        "type": hash_type,
        "value": value,
        "tags": tags,
    }


def generate_url_ioc() -> dict:
    """Generate a random URL IOC."""
    domain = random.choice(TEST_DOMAINS)
    paths = [
        "/download/malware.exe",
        "/api/c2/beacon",
        "/login.php",
        "/wp-admin/upload.php",
        "/update/payload",
        "/gate.php",
        f"/download/{random.randint(1000, 9999)}",
    ]

    url = f"https://{domain}{random.choice(paths)}"

    # Sometimes add query params
    if random.random() > 0.5:
        url += f"?id={random.randint(1, 1000)}"

    return {
        "type": "url",
        "value": url,
        "tags": random.sample(TAGS, random.randint(1, 3)),
    }


def generate_ioc(ioc_type: str = "mixed") -> dict:
    """Generate a random IOC of the specified type."""
    generators = {
        "ip": generate_ip_ioc,
        "domain": generate_domain_ioc,
        "hash": generate_hash_ioc,
        "url": generate_url_ioc,
    }

    if ioc_type == "mixed":
        generator = random.choice(list(generators.values()))
    else:
        generator = generators.get(ioc_type)
        if not generator:
            raise ValueError(f"Unknown IOC type: {ioc_type}")

    ioc = generator()

    # Sometimes add threat actor or campaign tags
    if random.random() > 0.7:
        ioc["tags"].append(random.choice(THREAT_ACTORS))
    if random.random() > 0.8:
        ioc["tags"].append(random.choice(CAMPAIGNS))

    return ioc


def create_iocs(base_url: str, count: int, ioc_type: str) -> tuple[int, int]:
    """Create IOCs via the API."""
    created = 0
    failed = 0

    with httpx.Client(timeout=30.0) as client:
        for i in range(count):
            ioc = generate_ioc(ioc_type)

            try:
                resp = client.post(
                    f"{base_url}/api/v1/iocs/",
                    json=ioc,
                )

                if resp.status_code in (200, 201):
                    created += 1
                    print(f"✓ Created {ioc['type']}: {ioc['value'][:50]}")
                else:
                    failed += 1
                    print(f"✗ Failed to create {ioc['type']}: HTTP {resp.status_code}")

            except Exception as e:
                failed += 1
                print(f"✗ Error creating {ioc['type']}: {e}")

    return created, failed


def main():
    parser = argparse.ArgumentParser(description="Generate test data for Corvid API")
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of IOCs to create (default: 50)",
    )
    parser.add_argument(
        "--type",
        choices=["ip", "domain", "hash", "url", "mixed"],
        default="mixed",
        help="IOC type to create (default: mixed)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print IOCs without creating them",
    )

    args = parser.parse_args()

    print(f"Generating {args.count} {args.type} IOC(s)")
    print(f"Target: {args.url}")
    print()

    if args.dry_run:
        print("DRY RUN - IOCs will not be created")
        print()
        for i in range(args.count):
            ioc = generate_ioc(args.type)
            print(f"{ioc['type']}: {ioc['value']}")
            print(f"  Tags: {', '.join(ioc['tags'])}")
        return

    # Check API is available
    try:
        resp = httpx.get(f"{args.url}/health", timeout=5.0)
        if resp.status_code != 200:
            print(f"Warning: Health check returned {resp.status_code}")
    except Exception as e:
        print(f"Error: Cannot connect to {args.url}: {e}")
        sys.exit(1)

    created, failed = create_iocs(args.url, args.count, args.type)

    print()
    print("=" * 40)
    print(f"Created: {created}")
    print(f"Failed:  {failed}")
    print("=" * 40)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
