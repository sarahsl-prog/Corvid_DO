/**
 * Zustand store for graph filter state.
 */

import { create } from "zustand";
import type { IOCType } from "../types/api.ts";
import type { NodeType } from "../types/graph.ts";

interface FilterStoreState {
  severityRange: [number, number];
  confidenceThreshold: number;
  iocTypes: Set<IOCType>;
  nodeTypes: Set<NodeType>;
  sources: Set<string>;

  setSeverityRange: (range: [number, number]) => void;
  setConfidenceThreshold: (threshold: number) => void;
  toggleIOCType: (type: IOCType) => void;
  toggleNodeType: (type: NodeType) => void;
  toggleSource: (source: string) => void;
  resetFilters: () => void;
}

export const useFilterStore = create<FilterStoreState>((set) => ({
  severityRange: [0, 10],
  confidenceThreshold: 0,
  iocTypes: new Set(),
  nodeTypes: new Set(),
  sources: new Set(),

  setSeverityRange: (range) => set({ severityRange: range }),

  setConfidenceThreshold: (threshold) => set({ confidenceThreshold: threshold }),

  toggleIOCType: (type) =>
    set((state) => {
      const next = new Set(state.iocTypes);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return { iocTypes: next };
    }),

  toggleNodeType: (type) =>
    set((state) => {
      const next = new Set(state.nodeTypes);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return { nodeTypes: next };
    }),

  toggleSource: (source) =>
    set((state) => {
      const next = new Set(state.sources);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return { sources: next };
    }),

  resetFilters: () =>
    set({
      severityRange: [0, 10],
      confidenceThreshold: 0,
      iocTypes: new Set(),
      nodeTypes: new Set(),
      sources: new Set(),
    }),
}));
