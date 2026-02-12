/**
 * Cytoscape element types for the investigation graph.
 */

/** Node type discriminator for styling and filtering. */
export type NodeType = "ioc" | "cve" | "mitre";

/** Edge relationship types. */
export type EdgeType = "has_cve" | "uses_technique" | "related_ioc" | "enriched_by";

/** Cytoscape node element (data portion). */
export interface CyNodeData {
  id: string;
  label: string;
  nodeType: NodeType;
  /** Only present on IOC nodes */
  iocType?: string;
  severity?: number;
  confidence?: number;
  summary?: string;
  /** Full result item for the detail panel */
  resultData?: Record<string, unknown>;
}

/** Cytoscape edge element (data portion). */
export interface CyEdgeData {
  id?: string;
  source: string;
  target: string;
  edgeType: EdgeType;
  label?: string;
}

/** Full Cytoscape node element. */
export interface CyNode {
  data: CyNodeData;
}

/** Full Cytoscape edge element. */
export interface CyEdge {
  data: CyEdgeData;
}

/** Union of node or edge — passed to Cytoscape's elements array. */
export type CyElement = CyNode | CyEdge;

/** Available layout algorithms. */
export type LayoutName = "dagre" | "cose-bilkent" | "concentric" | "breadthfirst" | "grid";
