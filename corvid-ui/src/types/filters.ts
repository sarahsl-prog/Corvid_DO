/**
 * Filter state types for the investigation graph.
 */

import type { IOCType } from "./api.ts";
import type { NodeType } from "./graph.ts";

export interface FilterState {
  /** Severity range filter [min, max], 0-10 scale. */
  severityRange: [number, number];

  /** Confidence threshold — hide nodes below this value. */
  confidenceThreshold: number;

  /** Which IOC types to show (empty = show all). */
  iocTypes: Set<IOCType>;

  /** Which node types to show (empty = show all). */
  nodeTypes: Set<NodeType>;

  /** Which enrichment sources to highlight (empty = highlight none). */
  sources: Set<string>;
}

export const DEFAULT_FILTERS: FilterState = {
  severityRange: [0, 10],
  confidenceThreshold: 0,
  iocTypes: new Set(),
  nodeTypes: new Set(),
  sources: new Set(),
};
