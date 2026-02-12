/**
 * IOC type detection patterns — mirrors backend _IOC_PATTERNS
 * from corvid/api/models/ioc.py.
 */

import type { IOCType } from "../types/api.ts";

/** Compiled regex patterns for client-side IOC type detection. */
const IOC_PATTERNS: Record<IOCType, RegExp> = {
  hash_md5: /^[a-fA-F0-9]{32}$/,
  hash_sha1: /^[a-fA-F0-9]{40}$/,
  hash_sha256: /^[a-fA-F0-9]{64}$/,
  domain: /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/,
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  url: /^https?:\/\/\S+$/,
  ip: /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/,
};

/**
 * Detection order matters: check more specific patterns first.
 * e.g. a 32-char hex string should match hash_md5 before domain.
 */
const DETECTION_ORDER: IOCType[] = [
  "hash_sha256",
  "hash_sha1",
  "hash_md5",
  "email",
  "url",
  "ip",
  "domain",
];

/**
 * Auto-detect the IOC type from a raw value string.
 * Returns null if no pattern matches.
 */
export function detectIOCType(value: string): IOCType | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  for (const type of DETECTION_ORDER) {
    if (IOC_PATTERNS[type].test(trimmed)) {
      return type;
    }
  }
  return null;
}

/** Human-readable labels for IOC types. */
export const IOC_TYPE_LABELS: Record<IOCType, string> = {
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  hash_md5: "MD5 Hash",
  hash_sha1: "SHA-1 Hash",
  hash_sha256: "SHA-256 Hash",
  email: "Email",
};

/** All supported IOC types for dropdown population. */
export const ALL_IOC_TYPES: IOCType[] = [
  "ip",
  "domain",
  "url",
  "hash_md5",
  "hash_sha1",
  "hash_sha256",
  "email",
];

/**
 * Map a severity score (0-10) to a hex color.
 * Interpolates between green → yellow → red.
 */
export function severityToColor(severity: number): string {
  if (severity <= 0) return "#22c55e";
  if (severity <= 3) return "#84cc16";
  if (severity <= 5) return "#eab308";
  if (severity <= 7) return "#f97316";
  if (severity <= 9) return "#ef4444";
  return "#dc2626";
}

/** Map a confidence score (0-1) to a label. */
export function confidenceLabel(confidence: number): string {
  if (confidence >= 0.8) return "High";
  if (confidence >= 0.5) return "Medium";
  return "Low";
}
