/**
 * Main investigation board — composes the graph canvas, input bar,
 * detail panel, filter toolbar, layout switcher, and overlays into the full workspace.
 *
 * Features:
 * - Filter toolbar (toggleable)
 * - Layout switcher
 * - History drawer
 * - Keyboard shortcuts (1-5, Escape, Delete, F, R)
 */

import { useCallback, useEffect, useState, useRef } from "react";
import { Filter, History as HistoryIcon } from "lucide-react";
import { useGraphStore } from "../stores/graphStore.ts";
import { useHistoryStore } from "../stores/historyStore.ts";
import { useAnalysis } from "../hooks/useAnalysis.ts";
import { analysisToElements } from "../lib/graphTransforms.ts";
import type { AnalyzeRequest } from "../types/api.ts";
import { GraphCanvas } from "./GraphCanvas.tsx";
import { IOCInputBar } from "./IOCInputBar.tsx";
import { DetailPanel } from "./DetailPanel.tsx";
import { LoadingOverlay } from "./LoadingOverlay.tsx";
import { SeverityLegend } from "./SeverityLegend.tsx";
import { FilterToolbar } from "./FilterToolbar.tsx";
import { LayoutSwitcher } from "./LayoutSwitcher.tsx";
import { HistoryDrawer } from "./HistoryDrawer.tsx";

export function InvestigationBoard() {
  const [showFilters, setShowFilters] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  // Graph store
  const addElements = useGraphStore((s) => s.addElements);
  const selectedNodeId = useGraphStore((s) => s.selectedNodeId);
  const selectNode = useGraphStore((s) => s.selectNode);
  const nodes = useGraphStore((s) => s.nodes);
  const edges = useGraphStore((s) => s.edges);
  const clearGraph = useGraphStore((s) => s.clearGraph);
  const removeNode = useGraphStore((s) => s.removeNode);
  const cyInstance = useGraphStore((s) => s.cyInstance);

  // History store
  const saveSession = useHistoryStore((s) => s.saveSession);

  // Analysis hook
  const { analyze, loading, error, response } = useAnalysis();

  // Save session when analysis completes
  const prevResponseRef = useRef(response);
  useEffect(() => {
    if (response && response !== prevResponseRef.current) {
      prevResponseRef.current = response;
      if (response.results.length > 0) {
        saveSession(
          `Investigation ${new Date().toLocaleTimeString()}`,
          nodes,
          edges,
          response.results
        );
      }
    }
  }, [response, nodes, edges, saveSession]);

  // Analysis submission handler
  const handleSubmit = useCallback(
    async (request: AnalyzeRequest) => {
      const resp = await analyze(request);
      if (resp) {
        const { nodes: newNodes, edges: newEdges } = analysisToElements(resp);
        addElements(newNodes, newEdges);
      }
    },
    [analyze, addElements]
  );

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      switch (e.key) {
        case "Escape":
          // Deselect current node / close panels
          selectNode(null);
          setShowFilters(false);
          break;

        case "Delete":
        case "Backspace":
          // Remove selected node
          if (selectedNodeId) {
            removeNode(selectedNodeId);
          }
          break;

        case "f":
        case "F":
          // Fit graph to viewport
          if (cyInstance) {
            cyInstance.fit(undefined, 50);
          }
          break;

        case "r":
        case "R":
          // Reset filters (if open)
          if (showFilters && e.ctrlKey) {
            e.preventDefault();
          }
          break;

        case "h":
        case "H":
          if (!e.ctrlKey) {
            setShowHistory((prev) => !prev);
          }
          break;

        // Layout shortcuts (1-5)
        case "1":
        case "2":
        case "3":
        case "4":
        case "5":
          // Prevent default only when not in input
          if (!e.ctrlKey && !e.metaKey) {
            const layouts = ["dagre", "cose-bilkent", "concentric", "breadthfirst", "grid"] as const;
            const index = parseInt(e.key) - 1;
            if (layouts[index]) {
              const setLayout = useGraphStore.getState().setLayout;
              setLayout(layouts[index]);
            }
          }
          break;

        default:
          break;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectedNodeId, selectNode, removeNode, cyInstance, showFilters]);

  // Ctrl+K to focus input (vim-style / also works without /)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        (e.ctrlKey && e.key === "k") ||
        (e.key === "/" && !(e.target instanceof HTMLInputElement))
      ) {
        e.preventDefault();
        const input = document.querySelector(
          '[data-testid="ioc-input-bar"] input'
        ) as HTMLInputElement;
        input?.focus();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className="flex h-full flex-col" data-testid="investigation-board">
      {/* Top bar: Controls + IOC input */}
      <div className="shrink-0 border-b border-bg-tertiary p-3 space-y-3">
        {/* Toolbar row */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                showFilters
                  ? "bg-accent/20 text-accent"
                  : "bg-bg-secondary hover:bg-bg-tertiary text-text-primary"
              }`}
              title="Toggle filter panel (F)"
            >
              <Filter className="h-4 w-4" />
              Filters
            </button>

            <LayoutSwitcher />

            <button
              onClick={() => setShowHistory(!showHistory)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                showHistory
                  ? "bg-accent/20 text-accent"
                  : "bg-bg-secondary hover:bg-bg-tertiary text-text-primary"
              }`}
              title="Toggle history drawer (H)"
            >
              <HistoryIcon className="h-4 w-4" />
              History
            </button>

            <button
              onClick={() => clearGraph()}
              className="px-3 py-2 rounded-md bg-bg-secondary hover:bg-severity-9/20 text-text-secondary hover:text-severity-9 text-sm font-medium transition-colors"
              title="Clear graph"
            >
              Clear
            </button>
          </div>

          <div className="flex-1">
            <IOCInputBar onSubmit={handleSubmit} disabled={loading} />
          </div>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-severity-9/20 border-b border-severity-9 px-4 py-2 text-sm text-severity-9">
          Analysis error: {error}
        </div>
      )}

      {/* Main content area */}
      <div className="relative flex min-h-0 flex-1">
        {/* Optional filter toolbar */}
        {showFilters && <FilterToolbar onClose={() => setShowFilters(false)} />}

        {/* Graph canvas */}
        <div className="relative min-w-0 flex-1">
          <GraphCanvas />
          <LoadingOverlay loading={loading} />
          <SeverityLegend />

          {/* Keyboard shortcuts hint */}
          <div className="absolute bottom-4 left-4 px-3 py-2 bg-bg-secondary/90 backdrop-blur rounded-lg border border-bg-tertiary text-xs text-text-muted">
            <div className="flex items-center gap-4">
              <span><kbd className="font-mono">Esc</kbd> deselect</span>
              <span><kbd className="font-mono">F</kbd> fit</span>
              <span><kbd className="font-mono">1-5</kbd> layouts</span>
              <span><kbd className="font-mono">/</kbd> search</span>
            </div>
          </div>
        </div>

        {/* Detail panel (conditionally rendered) */}
        {selectedNodeId && <DetailPanel />}
      </div>

      {/* History drawer */}
      <HistoryDrawer isOpen={showHistory} onClose={() => setShowHistory(false)} />
    </div>
  );
}
