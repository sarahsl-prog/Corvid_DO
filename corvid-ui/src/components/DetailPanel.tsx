/**
 * Detail panel — shows full data for the selected graph node.
 *
 * Slides in from the right when a node is selected.
 */

import { X, ExternalLink, Shield, Crosshair, ShieldAlert } from "lucide-react";
import { useGraphStore } from "../stores/graphStore.ts";
import { SeverityGauge } from "./SeverityGauge.tsx";
import { confidenceLabel } from "../lib/constants.ts";
import type { CyNodeData } from "../types/graph.ts";
import type { AnalysisResultItem } from "../types/api.ts";

export function DetailPanel() {
  const { selectedNodeId, nodes, selectNode } = useGraphStore();

  if (!selectedNodeId) return null;

  const selectedNode = nodes.find((n) => n.data.id === selectedNodeId);
  if (!selectedNode) return null;

  const nodeData: CyNodeData = selectedNode.data;
  const resultData = nodeData.resultData as unknown as AnalysisResultItem | undefined;

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
          {/* Severity */}
          <Section title="Severity">
            <SeverityGauge severity={resultData.severity} />
          </Section>

          {/* Confidence */}
          <Section title="Confidence">
            <span className="text-sm text-text-secondary">
              {(resultData.confidence * 100).toFixed(0)}% —{" "}
              {confidenceLabel(resultData.confidence)}
            </span>
          </Section>

          {/* Summary */}
          <Section title="Summary">
            <p className="text-sm leading-relaxed text-text-secondary">
              {resultData.summary}
            </p>
          </Section>

          {/* Related CVEs */}
          {resultData.related_cves.length > 0 && (
            <Section title="Related CVEs">
              <ul className="flex flex-col gap-1">
                {resultData.related_cves.map((cve) => (
                  <li key={cve} className="flex items-center gap-1 text-sm">
                    <ShieldAlert className="h-3 w-3 text-node-cve" />
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent hover:underline"
                    >
                      {cve}
                    </a>
                    <ExternalLink className="h-3 w-3 text-text-muted" />
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {/* MITRE Techniques */}
          {resultData.mitre_techniques.length > 0 && (
            <Section title="MITRE ATT&CK">
              <ul className="flex flex-col gap-1">
                {resultData.mitre_techniques.map((tech) => (
                  <li key={tech} className="flex items-center gap-1 text-sm">
                    <Crosshair className="h-3 w-3 text-node-mitre" />
                    <a
                      href={`https://attack.mitre.org/techniques/${tech.replace(".", "/")}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent hover:underline"
                    >
                      {tech}
                    </a>
                    <ExternalLink className="h-3 w-3 text-text-muted" />
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {/* Enrichments */}
          {Object.keys(resultData.enrichments).length > 0 && (
            <Section title="Enrichments">
              {Object.entries(resultData.enrichments).map(([source, data]) => (
                <div
                  key={source}
                  className="mb-2 rounded border border-bg-tertiary bg-bg-primary p-2"
                >
                  <h5 className="mb-1 text-xs font-medium uppercase text-text-muted">
                    {source}
                  </h5>
                  <pre className="overflow-x-auto text-xs text-text-secondary">
                    {JSON.stringify(data, null, 2)}
                  </pre>
                </div>
              ))}
            </Section>
          )}

          {/* Recommended Actions */}
          {resultData.recommended_actions.length > 0 && (
            <Section title="Recommended Actions">
              <ul className="flex flex-col gap-1">
                {resultData.recommended_actions.map((action, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm text-text-secondary"
                  >
                    <span className="mt-0.5 text-accent">&#x2022;</span>
                    {action}
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* CVE node detail */}
      {nodeData.nodeType === "cve" && (
        <div className="p-4">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${nodeData.label}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-accent hover:underline"
          >
            View on NVD <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      )}

      {/* MITRE node detail */}
      {nodeData.nodeType === "mitre" && (
        <div className="p-4">
          <a
            href={`https://attack.mitre.org/techniques/${nodeData.label.replace(".", "/")}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-accent hover:underline"
          >
            View on MITRE ATT&CK <ExternalLink className="h-3 w-3" />
          </a>
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
      <h4 className="mb-1 text-xs font-medium uppercase tracking-wider text-text-muted">
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
