/**
 * CVE detail card — shows CVE ID, CVSS score badge, and NVD link.
 *
 * Used in the DetailPanel when an IOC has related CVEs,
 * and also when a CVE node is selected directly.
 */

import { ExternalLink, ShieldAlert } from "lucide-react";
import { severityToColor } from "../lib/constants.ts";

interface CVECardProps {
  /** CVE identifier, e.g. "CVE-2024-21762". */
  cveId: string;
  /** CVSS base score 0-10, if known. */
  cvssScore?: number | null;
  /** Short description of the vulnerability. */
  description?: string;
}

export function CVECard({ cveId, cvssScore, description }: CVECardProps) {
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;

  return (
    <div
      className="rounded-lg border border-bg-tertiary bg-bg-primary p-3"
      data-testid="cve-card"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-node-cve" />
          <a
            href={nvdUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-medium text-accent hover:underline"
          >
            {cveId}
          </a>
          <ExternalLink className="h-3 w-3 text-text-muted" />
        </div>

        {cvssScore != null && (
          <span
            className="rounded-full px-2 py-0.5 text-xs font-bold text-bg-primary"
            style={{ backgroundColor: severityToColor(cvssScore) }}
            data-testid="cvss-badge"
          >
            {cvssScore.toFixed(1)}
          </span>
        )}
      </div>

      {description && (
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">
          {description}
        </p>
      )}
    </div>
  );
}
