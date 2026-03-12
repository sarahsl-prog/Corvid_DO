/**
 * Zustand store for investigation session history.
 *
 * Persists graph state so users can restore past investigations.
 */

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { CyNode, CyEdge } from "../types/graph.ts";
import type { AnalysisResultItem } from "../types/api.ts";

interface InvestigationSession {
  id: string;
  name: string;
  timestamp: number;
  nodes: CyNode[];
  edges: CyEdge[];
  results: AnalysisResultItem[];
}

interface HistoryStoreState {
  sessions: InvestigationSession[];
  maxSessions: number;

  saveSession: (name: string, nodes: CyNode[], edges: CyEdge[], results: AnalysisResultItem[]) => void;
  loadSession: (id: string) => InvestigationSession | null;
  deleteSession: (id: string) => void;
  clearHistory: () => void;
  setMaxSessions: (count: number) => void;
}

const MAX_SESSIONS_DEFAULT = 20;

export const useHistoryStore = create<HistoryStoreState>()(
  persist(
    (set, get) => ({
      sessions: [],
      maxSessions: MAX_SESSIONS_DEFAULT,

      saveSession: (name, nodes, edges, results) =>
        set((state) => {
          const newSession: InvestigationSession = {
            id: crypto.randomUUID(),
            name: name || `Investigation ${state.sessions.length + 1}`,
            timestamp: Date.now(),
            nodes: [...nodes],
            edges: [...edges],
            results: [...results],
          };

          // Keep only maxSessions most recent
          const updatedSessions = [newSession, ...state.sessions].slice(0, state.maxSessions);
          return { sessions: updatedSessions };
        }),

      loadSession: (id) => {
        return get().sessions.find((s) => s.id === id) || null;
      },

      deleteSession: (id) =>
        set((state) => ({
          sessions: state.sessions.filter((s) => s.id !== id),
        })),

      clearHistory: () => set({ sessions: [] }),

      setMaxSessions: (count) => set({ maxSessions: count }),
    }),
    {
      name: "corvid-investigation-history",
      version: 1,
    },
  ),
);
