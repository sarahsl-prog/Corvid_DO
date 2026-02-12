/**
 * MITRE ATT&CK technique card — shows technique ID, name, tactics, and link.
 *
 * Used in the DetailPanel for IOC analysis results and
 * when a MITRE technique node is selected directly.
 */

import { ExternalLink, Crosshair } from "lucide-react";

/** Color palette for MITRE ATT&CK tactics. */
const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "#ef4444",
  execution: "#f97316",
  persistence: "#eab308",
  "privilege-escalation": "#84cc16",
  "defense-evasion": "#22c55e",
  "credential-access": "#06b6d4",
  discovery: "#3b82f6",
  "lateral-movement": "#6366f1",
  collection: "#8b5cf6",
  "command-and-control": "#a855f7",
  exfiltration: "#d946ef",
  impact: "#ec4899",
};

interface MitreOverlayProps {
  /** Technique ID, e.g. "T1071.001". */
  techniqueId: string;
  /** Human-readable technique name, if known. */
  name?: string;
  /** Tactic(s) this technique belongs to. */
  tactics?: string[];
  /** Short description. */
  description?: string;
}

export function MitreOverlay({
  techniqueId,
  name,
  tactics,
  description,
}: MitreOverlayProps) {
  const mitreUrl = `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}`;

  return (
    <div
      className="rounded-lg border border-bg-tertiary bg-bg-primary p-3"
      data-testid="mitre-card"
    >
      <div className="flex items-center gap-2">
        <Crosshair className="h-4 w-4 text-node-mitre" />
        <a
          href={mitreUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm font-medium text-accent hover:underline"
        >
          {techniqueId}
        </a>
        <ExternalLink className="h-3 w-3 text-text-muted" />
      </div>

      {name && (
        <p className="mt-1 text-sm text-text-primary" data-testid="mitre-name">
          {name}
        </p>
      )}

      {tactics && tactics.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1" data-testid="mitre-tactics">
          {tactics.map((tactic) => (
            <span
              key={tactic}
              className="rounded-full px-2 py-0.5 text-xs font-medium text-bg-primary"
              style={{
                backgroundColor: TACTIC_COLORS[tactic] ?? "#6b7280",
              }}
            >
              {tactic.replace(/-/g, " ")}
            </span>
          ))}
        </div>
      )}

      {description && (
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">
          {description}
        </p>
      )}
    </div>
  );
}
