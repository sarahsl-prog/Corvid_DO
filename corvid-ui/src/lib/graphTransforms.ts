/**
 * Transforms Corvid API responses into Cytoscape graph elements.
 */

import type { AnalyzeResponse, AnalysisResultItem } from "../types/api.ts";
import type { CyNode, CyEdge } from "../types/graph.ts";

/**
 * Generate a deterministic node ID for an IOC.
 */
export function iocNodeId(type: string, value: string): string {
  return `ioc-${type}-${value}`;
}

/**
 * Generate a deterministic node ID for a CVE.
 */
export function cveNodeId(cveId: string): string {
  return `cve-${cveId}`;
}

/**
 * Generate a deterministic node ID for a MITRE technique.
 */
export function mitreNodeId(techniqueId: string): string {
  return `mitre-${techniqueId}`;
}

/**
 * Convert a single AnalysisResultItem into graph elements.
 */
export function resultToElements(result: AnalysisResultItem): {
  nodes: CyNode[];
  edges: CyEdge[];
} {
  const nodes: CyNode[] = [];
  const edges: CyEdge[] = [];

  const iocId = iocNodeId(result.ioc.type, result.ioc.value);

  // IOC node
  nodes.push({
    data: {
      id: iocId,
      label: result.ioc.value,
      nodeType: "ioc",
      iocType: result.ioc.type,
      severity: result.severity,
      confidence: result.confidence,
      summary: result.summary,
      resultData: result as unknown as Record<string, unknown>,
    },
  });

  // CVE nodes + edges
  for (const cve of result.related_cves) {
    const cId = cveNodeId(cve);
    nodes.push({
      data: { id: cId, label: cve, nodeType: "cve" },
    });
    edges.push({
      data: { source: iocId, target: cId, edgeType: "has_cve" },
    });
  }

  // MITRE technique nodes + edges
  for (const technique of result.mitre_techniques) {
    const mId = mitreNodeId(technique);
    nodes.push({
      data: { id: mId, label: technique, nodeType: "mitre" },
    });
    edges.push({
      data: { source: iocId, target: mId, edgeType: "uses_technique" },
    });
  }

  return { nodes, edges };
}

/**
 * Deduplicate nodes by ID — keeps the first occurrence.
 */
export function deduplicateNodes(nodes: CyNode[]): CyNode[] {
  const seen = new Set<string>();
  const result: CyNode[] = [];
  for (const node of nodes) {
    if (!seen.has(node.data.id)) {
      seen.add(node.data.id);
      result.push(node);
    }
  }
  return result;
}

/**
 * Convert a full AnalyzeResponse into deduplicated Cytoscape elements.
 */
export function analysisToElements(response: AnalyzeResponse): {
  nodes: CyNode[];
  edges: CyEdge[];
} {
  const allNodes: CyNode[] = [];
  const allEdges: CyEdge[] = [];

  for (const result of response.results) {
    const { nodes, edges } = resultToElements(result);
    allNodes.push(...nodes);
    allEdges.push(...edges);
  }

  return {
    nodes: deduplicateNodes(allNodes),
    edges: allEdges,
  };
}
