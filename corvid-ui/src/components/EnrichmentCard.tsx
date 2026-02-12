/**
 * Enrichment card — displays per-source enrichment data
 * with structured key-value rendering instead of raw JSON.
 */

import { Database, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";

interface EnrichmentCardProps {
  /** Source name, e.g. "abuseipdb", "urlhaus", "nvd". */
  source: string;
  /** Enrichment data from the API — can be any structure. */
  data: unknown;
}

/** Known field labels for common enrichment sources. */
const SOURCE_FIELD_LABELS: Record<string, Record<string, string>> = {
  abuseipdb: {
    abuse_confidence_score: "Abuse Confidence",
    total_reports: "Total Reports",
    country_code: "Country",
    isp: "ISP",
    usage_type: "Usage Type",
    domain: "Domain",
    is_tor: "Tor Exit Node",
    is_whitelisted: "Whitelisted",
    last_reported_at: "Last Reported",
  },
  urlhaus: {
    threat: "Threat Type",
    urls_hosted: "URLs Hosted",
    url_status: "Status",
    date_added: "Date Added",
    tags: "Tags",
    reference: "Reference",
  },
  nvd: {
    cve_id: "CVE ID",
    cvss_score: "CVSS Score",
    severity: "Severity",
    description: "Description",
    published: "Published",
  },
};

export function EnrichmentCard({ source, data }: EnrichmentCardProps) {
  const [expanded, setExpanded] = useState(false);

  if (data == null) return null;

  const entries = typeof data === "object" && !Array.isArray(data)
    ? Object.entries(data as Record<string, unknown>)
    : [];

  const labelMap = SOURCE_FIELD_LABELS[source.toLowerCase()] ?? {};

  // Separate "important" fields (those with known labels) from the rest
  const knownEntries = entries.filter(([key]) => key in labelMap);
  const otherEntries = entries.filter(([key]) => !(key in labelMap));

  return (
    <div
      className="rounded-lg border border-bg-tertiary bg-bg-primary"
      data-testid="enrichment-card"
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-3 text-left"
        type="button"
      >
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-node-ioc" />
          <span className="text-sm font-medium uppercase text-text-primary">
            {source}
          </span>
          <span className="rounded bg-bg-tertiary px-1.5 py-0.5 text-xs text-text-muted">
            {entries.length} fields
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-text-muted" />
        ) : (
          <ChevronDown className="h-4 w-4 text-text-muted" />
        )}
      </button>

      {/* Summary row — always visible, show top known fields */}
      {knownEntries.length > 0 && !expanded && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-bg-tertiary px-3 pb-3 pt-2">
          {knownEntries.slice(0, 3).map(([key, value]) => (
            <div key={key} className="text-xs">
              <span className="text-text-muted">{labelMap[key]}: </span>
              <span className="font-medium text-text-primary">
                {formatValue(value)}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-bg-tertiary p-3">
          <dl className="flex flex-col gap-2" data-testid="enrichment-details">
            {/* Known fields first */}
            {knownEntries.map(([key, value]) => (
              <div key={key} className="flex items-start gap-2 text-xs">
                <dt className="w-28 shrink-0 text-text-muted">{labelMap[key]}</dt>
                <dd className="break-all text-text-primary">{formatValue(value)}</dd>
              </div>
            ))}

            {/* Other fields */}
            {otherEntries.map(([key, value]) => (
              <div key={key} className="flex items-start gap-2 text-xs">
                <dt className="w-28 shrink-0 font-mono text-text-muted">{key}</dt>
                <dd className="break-all text-text-primary">{formatValue(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

/** Format a value for display — handles primitives, arrays, and objects. */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(", ");
  return JSON.stringify(value);
}
