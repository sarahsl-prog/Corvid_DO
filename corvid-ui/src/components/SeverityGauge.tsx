/**
 * Color-coded severity gauge — 0 (green) to 10 (red).
 */

import { severityToColor } from "../lib/constants.ts";

interface SeverityGaugeProps {
  severity: number | undefined | null;
}

export function SeverityGauge({ severity }: SeverityGaugeProps) {
  if (severity == null) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-text-muted text-sm">Severity: N/A</span>
      </div>
    );
  }

  const color = severityToColor(severity);
  const percentage = (severity / 10) * 100;

  return (
    <div className="flex items-center gap-3" data-testid="severity-gauge">
      {/* Bar */}
      <div className="h-2 flex-1 rounded-full bg-bg-tertiary">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${percentage}%`, backgroundColor: color }}
        />
      </div>
      {/* Score */}
      <span
        className="text-lg font-bold"
        style={{ color }}
        data-testid="severity-score"
      >
        {severity.toFixed(1)}
      </span>
    </div>
  );
}
