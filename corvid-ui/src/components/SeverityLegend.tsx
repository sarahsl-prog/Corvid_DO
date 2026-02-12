/**
 * Fixed legend overlay on the graph canvas showing the severity color scale.
 */

export function SeverityLegend() {
  return (
    <div
      className="absolute bottom-3 left-3 z-10 flex items-center gap-2 rounded-md bg-bg-secondary/90 px-3 py-2 text-xs text-text-secondary"
      data-testid="severity-legend"
    >
      <span>0</span>
      <div className="severity-gradient h-2 w-24 rounded-full" />
      <span>10</span>
      <span className="ml-2 text-text-muted">Severity</span>
    </div>
  );
}
