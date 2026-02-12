/**
 * Detail panel — shows full data for the selected graph node.
 *
 * Slides in from the right when a node is selected.
 * Uses dedicated card components for CVEs, MITRE techniques, and enrichments.
 * Includes an "Expand" button that re-analyzes the IOC and adds new nodes.
 */

import { useState } from "react";
import { X, Shield, Crosshair, ShieldAlert, RefreshCw, Loader2 } from "lucide-react";
import { useGraphStore } from "../stores/graphStore.ts";
import { useAnalysis } from "../hooks/useAnalysis.ts";
import { analysisToElements } from "../lib/graphTransforms.ts";
import { SeverityGauge } from "./SeverityGauge.tsx";
import { CVECard } from "./CVECard.tsx";
import { MitreOverlay } from "./MitreOverlay.tsx";
import { EnrichmentCard } from "./EnrichmentCard.tsx";
import { confidenceLabel } from "../lib/constants.ts";
import type { CyNodeData } from "../types/graph.ts";
import type { AnalysisResultItem } from "../types/api.ts";

export function DetailPanel() {
  const { selectedNodeId, nodes, selectNode, addElements } = useGraphStore();
  const { analyze, loading: expandLoading } = useAnalysis();
  const [expandError, setExpandError] = useState<string | null>(null);

  if (!selectedNodeId) return null;

  const selectedNode = nodes.find((n) => n.data.id === selectedNodeId);
  if (!selectedNode) return null;

  const nodeData: CyNodeData = selectedNode.data;
  const resultData = nodeData.resultData as unknown as AnalysisResultItem | undefined;

  /**
   * Expand: re-submit this IOC for analysis to discover additional relationships.
   * New nodes/edges are added to the existing graph (deduped by ID).
   */
  const handleExpand = async () => {
    if (!resultData) return;
    setExpandError(null);

    const response = await analyze({
      iocs: [resultData.ioc],
      context: "Expansion of existing IOC — fetch additional relationships",
      priority: "high",
    });

    if (response) {
      const { nodes: newNodes, edges: newEdges } = analysisToElements(response);
      addElements(newNodes, newEdges);
    } else {
      setExpandError("Expansion failed — check API connectivity");
    }
  };

  return (
    <div
      className="flex h-full w-80 flex-col overflow-y-auto border-l border-bg-tertiary bg-bg-secondary"
      data-testid="detail-panel"
    >
      {/* Header */}
      <div className="flex items-start justify-between border-b border-bg-tertiary p-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <NodeTypeIcon nodeType={nodeData.nodeType} />
            <span className="rounded bg-bg-tertiary px-2 py-0.5 text-xs uppercase text-text-secondary">
              {nodeData.nodeType}
            </span>
            {nodeData.iocType && (
              <span className="rounded bg-bg-tertiary px-2 py-0.5 text-xs text-text-muted">
                {nodeData.iocType}
              </span>
            )}
          </div>
          <p className="mt-1 break-all text-sm font-medium text-text-primary">
            {nodeData.label}
          </p>
        </div>
        <button
          onClick={() => selectNode(null)}
          className="ml-2 rounded p-1 text-text-muted hover:text-text-primary"
          aria-label="Close detail panel"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* IOC-specific detail sections */}
      {nodeData.nodeType === "ioc" && resultData && (
        <div className="flex flex-col gap-4 p-4">
          {/* Expand button */}
          <button
            onClick={handleExpand}
            disabled={expandLoading}
            className="flex items-center justify-center gap-2 rounded-md border border-accent bg-accent/10 px-3 py-2 text-sm font-medium text-accent hover:bg-accent/20 disabled:opacity-50"
            data-testid="expand-button"
          >
            {expandLoading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Expanding...
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4" />
                Expand &amp; Enrich
              </>
            )}
          </button>

          {expandError && (
            <p className="text-xs text-severity-9">{expandError}</p>
          )}

          {/* Severity */}
          <Section title="Severity">
            <SeverityGauge severity={resultData.severity} />
          </Section>

          {/* Confidence */}
          <Section title="Confidence">
            <div className="flex items-center gap-2">
              <div className="h-2 flex-1 rounded-full bg-bg-tertiary">
                <div
                  className="h-full rounded-full bg-accent transition-all"
                  style={{ width: `${resultData.confidence * 100}%` }}
                />
              </div>
              <span className="text-sm font-medium text-text-primary">
                {(resultData.confidence * 100).toFixed(0)}%
              </span>
              <span className="text-xs text-text-muted">
                {confidenceLabel(resultData.confidence)}
              </span>
            </div>
          </Section>

          {/* Summary */}
          <Section title="Summary">
            <p className="text-sm leading-relaxed text-text-secondary">
              {resultData.summary}
            </p>
          </Section>

          {/* Related CVEs — using CVECard */}
          {resultData.related_cves.length > 0 && (
            <Section title={`Related CVEs (${resultData.related_cves.length})`}>
              <div className="flex flex-col gap-2">
                {resultData.related_cves.map((cve) => (
                  <CVECard key={cve} cveId={cve} />
                ))}
              </div>
            </Section>
          )}

          {/* MITRE Techniques — using MitreOverlay */}
          {resultData.mitre_techniques.length > 0 && (
            <Section title={`MITRE ATT&CK (${resultData.mitre_techniques.length})`}>
              <div className="flex flex-col gap-2">
                {resultData.mitre_techniques.map((tech) => (
                  <MitreOverlay key={tech} techniqueId={tech} />
                ))}
              </div>
            </Section>
          )}

          {/* Enrichments — using EnrichmentCard */}
          {Object.keys(resultData.enrichments).length > 0 && (
            <Section title={`Enrichments (${Object.keys(resultData.enrichments).length})`}>
              <div className="flex flex-col gap-2">
                {Object.entries(resultData.enrichments).map(([source, data]) => (
                  <EnrichmentCard key={source} source={source} data={data} />
                ))}
              </div>
            </Section>
          )}

          {/* Recommended Actions */}
          {resultData.recommended_actions.length > 0 && (
            <Section title="Recommended Actions">
              <ul className="flex flex-col gap-2">
                {resultData.recommended_actions.map((action, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 rounded border border-bg-tertiary bg-bg-primary p-2 text-sm text-text-secondary"
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5 accent-accent"
                      aria-label={`Mark action as done: ${action}`}
                    />
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* CVE node detail — using CVECard */}
      {nodeData.nodeType === "cve" && (
        <div className="p-4">
          <CVECard cveId={nodeData.label} />
        </div>
      )}

      {/* MITRE node detail — using MitreOverlay */}
      {nodeData.nodeType === "mitre" && (
        <div className="p-4">
          <MitreOverlay techniqueId={nodeData.label} />
        </div>
      )}
    </div>
  );
}

/** Collapsible section wrapper. */
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h4 className="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
        {title}
      </h4>
      {children}
    </div>
  );
}

/** Icon for each node type. */
function NodeTypeIcon({ nodeType }: { nodeType: string }) {
  switch (nodeType) {
    case "ioc":
      return <Shield className="h-4 w-4 text-node-ioc" />;
    case "cve":
      return <ShieldAlert className="h-4 w-4 text-node-cve" />;
    case "mitre":
      return <Crosshair className="h-4 w-4 text-node-mitre" />;
    default:
      return null;
  }
}
