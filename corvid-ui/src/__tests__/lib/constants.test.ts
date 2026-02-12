import { describe, it, expect } from "vitest";
import { detectIOCType, severityToColor, confidenceLabel } from "../../lib/constants.ts";

describe("detectIOCType", () => {
  it("detects IPv4 addresses", () => {
    expect(detectIOCType("203.0.113.42")).toBe("ip");
    expect(detectIOCType("10.0.0.1")).toBe("ip");
    expect(detectIOCType("255.255.255.255")).toBe("ip");
  });

  it("detects domains", () => {
    expect(detectIOCType("evil.example.com")).toBe("domain");
    expect(detectIOCType("malware.co")).toBe("domain");
  });

  it("detects URLs", () => {
    expect(detectIOCType("https://evil.example.com/payload")).toBe("url");
    expect(detectIOCType("http://malware.co/dropper.exe")).toBe("url");
  });

  it("detects MD5 hashes", () => {
    expect(detectIOCType("d41d8cd98f00b204e9800998ecf8427e")).toBe("hash_md5");
  });

  it("detects SHA-1 hashes", () => {
    expect(detectIOCType("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe("hash_sha1");
  });

  it("detects SHA-256 hashes", () => {
    const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(detectIOCType(sha256)).toBe("hash_sha256");
  });

  it("detects email addresses", () => {
    expect(detectIOCType("phish@evil.example.com")).toBe("email");
  });

  it("returns null for unknown format", () => {
    expect(detectIOCType("not-an-ioc")).toBeNull();
    expect(detectIOCType("")).toBeNull();
    expect(detectIOCType("   ")).toBeNull();
  });

  it("trims whitespace before detection", () => {
    expect(detectIOCType("  203.0.113.42  ")).toBe("ip");
  });
});

describe("severityToColor", () => {
  it("returns green for severity 0", () => {
    expect(severityToColor(0)).toBe("#22c55e");
  });

  it("returns yellow for severity 5", () => {
    expect(severityToColor(5)).toBe("#eab308");
  });

  it("returns red for severity 10", () => {
    expect(severityToColor(10)).toBe("#dc2626");
  });

  it("returns orange for severity 7", () => {
    expect(severityToColor(7)).toBe("#f97316");
  });
});

describe("confidenceLabel", () => {
  it("returns High for >= 0.8", () => {
    expect(confidenceLabel(0.85)).toBe("High");
    expect(confidenceLabel(1.0)).toBe("High");
  });

  it("returns Medium for >= 0.5", () => {
    expect(confidenceLabel(0.5)).toBe("Medium");
    expect(confidenceLabel(0.79)).toBe("Medium");
  });

  it("returns Low for < 0.5", () => {
    expect(confidenceLabel(0.2)).toBe("Low");
    expect(confidenceLabel(0)).toBe("Low");
  });
});
