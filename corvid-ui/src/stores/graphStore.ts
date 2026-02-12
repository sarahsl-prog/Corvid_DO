/**
 * Zustand store for the investigation graph state.
 *
 * Manages Cytoscape nodes, edges, selection, and active layout.
 */

import { create } from "zustand";
import type { CyNode, CyEdge, LayoutName } from "../types/graph.ts";

interface GraphState {
  /** Current graph nodes. */
  nodes: CyNode[];
  /** Current graph edges. */
  edges: CyEdge[];
  /** Currently selected node ID (null = nothing selected). */
  selectedNodeId: string | null;
  /** Active layout algorithm name. */
  activeLayout: LayoutName;

  /** Add nodes and edges to the graph, deduplicating by ID. */
  addElements: (newNodes: CyNode[], newEdges: CyEdge[]) => void;
  /** Remove a node and all edges connected to it. */
  removeNode: (nodeId: string) => void;
  /** Select a node by ID, or null to deselect. */
  selectNode: (nodeId: string | null) => void;
  /** Change the active layout algorithm. */
  setLayout: (layout: LayoutName) => void;
  /** Clear the entire graph. */
  clearGraph: () => void;
}

export const useGraphStore = create<GraphState>((set) => ({
  nodes: [],
  edges: [],
  selectedNodeId: null,
  activeLayout: "dagre",

  addElements: (newNodes, newEdges) =>
    set((state) => {
      const existingIds = new Set(state.nodes.map((n) => n.data.id));
      const uniqueNewNodes = newNodes.filter((n) => !existingIds.has(n.data.id));
      return {
        nodes: [...state.nodes, ...uniqueNewNodes],
        edges: [...state.edges, ...newEdges],
      };
    }),

  removeNode: (nodeId) =>
    set((state) => ({
      nodes: state.nodes.filter((n) => n.data.id !== nodeId),
      edges: state.edges.filter(
        (e) => e.data.source !== nodeId && e.data.target !== nodeId,
      ),
      selectedNodeId: state.selectedNodeId === nodeId ? null : state.selectedNodeId,
    })),

  selectNode: (nodeId) => set({ selectedNodeId: nodeId }),

  setLayout: (layout) => set({ activeLayout: layout }),

  clearGraph: () =>
    set({
      nodes: [],
      edges: [],
      selectedNodeId: null,
    }),
}));
