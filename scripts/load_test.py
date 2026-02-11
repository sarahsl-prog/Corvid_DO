#!/usr/bin/env python3
"""
load_test.py - Simple load testing script for Corvid API

Usage:
    python scripts/load_test.py [--url URL] [--requests N] [--concurrent N]

Options:
    --url URL       Target URL (default: http://localhost:8000)
    --requests N    Total number of requests to make (default: 100)
    --concurrent N  Number of concurrent requests (default: 10)
"""

import argparse
import asyncio
import random
import statistics
import time
from dataclasses import dataclass

import httpx


@dataclass
class RequestResult:
    """Result of a single request."""
    endpoint: str
    method: str
    status_code: int
    duration_ms: float
    success: bool
    error: str | None = None


class LoadTester:
    """Simple load testing client."""

    def __init__(self, base_url: str, concurrent: int = 10):
        self.base_url = base_url.rstrip("/")
        self.concurrent = concurrent
        self.results: list[RequestResult] = []
        self.semaphore = asyncio.Semaphore(concurrent)

        # Test data
        self.test_ips = [f"192.0.2.{i}" for i in range(1, 255)]
        self.test_domains = [f"test{i}.example.com" for i in range(1, 100)]

    async def make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        endpoint: str,
        json_data: dict | None = None,
    ) -> RequestResult:
        """Make a single request and record result."""
        async with self.semaphore:
            url = f"{self.base_url}{endpoint}"
            start = time.perf_counter()

            try:
                if method == "GET":
                    resp = await client.get(url)
                elif method == "POST":
                    resp = await client.post(url, json=json_data)
                elif method == "DELETE":
                    resp = await client.delete(url)
                else:
                    raise ValueError(f"Unknown method: {method}")

                duration_ms = (time.perf_counter() - start) * 1000
                success = 200 <= resp.status_code < 400

                return RequestResult(
                    endpoint=endpoint,
                    method=method,
                    status_code=resp.status_code,
                    duration_ms=duration_ms,
                    success=success,
                )
            except Exception as e:
                duration_ms = (time.perf_counter() - start) * 1000
                return RequestResult(
                    endpoint=endpoint,
                    method=method,
                    status_code=0,
                    duration_ms=duration_ms,
                    success=False,
                    error=str(e),
                )

    def generate_ioc_payload(self) -> dict:
        """Generate a random IOC payload."""
        ioc_type = random.choice(["ip", "domain", "hash_sha256", "url"])

        if ioc_type == "ip":
            value = random.choice(self.test_ips)
        elif ioc_type == "domain":
            value = random.choice(self.test_domains)
        elif ioc_type == "hash_sha256":
            value = "".join(random.choices("0123456789abcdef", k=64))
        else:  # url
            domain = random.choice(self.test_domains)
            value = f"https://{domain}/path/{random.randint(1, 1000)}"

        return {
            "type": ioc_type,
            "value": value,
            "tags": ["load-test"],
        }

    async def run_scenario(
        self,
        client: httpx.AsyncClient,
        num_requests: int,
    ) -> None:
        """Run a mixed scenario of API requests."""
        tasks = []

        for i in range(num_requests):
            # Mix of operations
            choice = random.random()

            if choice < 0.3:
                # 30% health checks
                task = self.make_request(client, "GET", "/health")
            elif choice < 0.5:
                # 20% list IOCs
                task = self.make_request(client, "GET", "/api/v1/iocs/")
            elif choice < 0.9:
                # 40% create IOCs
                payload = self.generate_ioc_payload()
                task = self.make_request(client, "POST", "/api/v1/iocs/", payload)
            else:
                # 10% list analyses
                task = self.make_request(client, "GET", "/api/v1/analyses/")

            tasks.append(task)

        results = await asyncio.gather(*tasks)
        self.results.extend(results)

    async def run(self, num_requests: int) -> None:
        """Run the load test."""
        print(f"Starting load test: {num_requests} requests, {self.concurrent} concurrent")
        print(f"Target: {self.base_url}")
        print()

        start_time = time.perf_counter()

        async with httpx.AsyncClient(timeout=30.0) as client:
            await self.run_scenario(client, num_requests)

        total_time = time.perf_counter() - start_time

        self.print_results(total_time, num_requests)

    def print_results(self, total_time: float, num_requests: int) -> None:
        """Print test results summary."""
        print("=" * 60)
        print("Load Test Results")
        print("=" * 60)
        print()

        # Overall stats
        successful = sum(1 for r in self.results if r.success)
        failed = len(self.results) - successful

        print(f"Total requests:     {len(self.results)}")
        print(f"Successful:         {successful} ({100*successful/len(self.results):.1f}%)")
        print(f"Failed:             {failed} ({100*failed/len(self.results):.1f}%)")
        print(f"Total time:         {total_time:.2f}s")
        print(f"Requests/second:    {num_requests/total_time:.2f}")
        print()

        # Latency stats
        durations = [r.duration_ms for r in self.results]
        print("Latency (ms):")
        print(f"  Min:              {min(durations):.2f}")
        print(f"  Max:              {max(durations):.2f}")
        print(f"  Mean:             {statistics.mean(durations):.2f}")
        print(f"  Median:           {statistics.median(durations):.2f}")
        print(f"  Std Dev:          {statistics.stdev(durations):.2f}")
        print(f"  P95:              {statistics.quantiles(durations, n=20)[18]:.2f}")
        print(f"  P99:              {statistics.quantiles(durations, n=100)[98]:.2f}")
        print()

        # Per-endpoint stats
        print("Per-endpoint breakdown:")
        endpoints = {}
        for r in self.results:
            key = f"{r.method} {r.endpoint}"
            if key not in endpoints:
                endpoints[key] = {"count": 0, "success": 0, "durations": []}
            endpoints[key]["count"] += 1
            if r.success:
                endpoints[key]["success"] += 1
            endpoints[key]["durations"].append(r.duration_ms)

        for endpoint, stats in sorted(endpoints.items()):
            success_rate = 100 * stats["success"] / stats["count"]
            avg_duration = statistics.mean(stats["durations"])
            print(f"  {endpoint}")
            print(f"    Count: {stats['count']}, Success: {success_rate:.1f}%, Avg: {avg_duration:.2f}ms")

        print()

        # Error summary
        errors = [r for r in self.results if r.error]
        if errors:
            print("Errors:")
            error_counts = {}
            for r in errors:
                error_counts[r.error] = error_counts.get(r.error, 0) + 1
            for error, count in sorted(error_counts.items(), key=lambda x: -x[1])[:5]:
                print(f"  {count}x: {error[:60]}")

        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Corvid API Load Tester")
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=100,
        help="Total number of requests (default: 100)",
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=10,
        help="Number of concurrent requests (default: 10)",
    )

    args = parser.parse_args()

    tester = LoadTester(args.url, args.concurrent)
    asyncio.run(tester.run(args.requests))


if __name__ == "__main__":
    main()
