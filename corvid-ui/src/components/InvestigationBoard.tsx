/**
 * Main investigation board — composes the graph canvas, input bar,
 * detail panel, and overlays into the full workspace.
 */

import { useCallback } from "react";
import { useGraphStore } from "../stores/graphStore.ts";
import { useAnalysis } from "../hooks/useAnalysis.ts";
import { analysisToElements } from "../lib/graphTransforms.ts";
import type { AnalyzeRequest } from "../types/api.ts";
import { GraphCanvas } from "./GraphCanvas.tsx";
import { IOCInputBar } from "./IOCInputBar.tsx";
import { DetailPanel } from "./DetailPanel.tsx";
import { LoadingOverlay } from "./LoadingOverlay.tsx";
import { SeverityLegend } from "./SeverityLegend.tsx";

export function InvestigationBoard() {
  const { addElements, selectedNodeId } = useGraphStore();
  const { analyze, loading, error } = useAnalysis();

  const handleSubmit = useCallback(
    async (request: AnalyzeRequest) => {
      const response = await analyze(request);
      if (response) {
        const { nodes, edges } = analysisToElements(response);
        addElements(nodes, edges);
      }
    },
    [analyze, addElements],
  );

  return (
    <div className="flex h-full flex-col" data-testid="investigation-board">
      {/* Top bar: IOC input */}
      <div className="shrink-0 border-b border-bg-tertiary p-3">
        <IOCInputBar onSubmit={handleSubmit} disabled={loading} />
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-severity-9/20 border-b border-severity-9 px-4 py-2 text-sm text-severity-9">
          Analysis error: {error}
        </div>
      )}

      {/* Main content: graph + detail panel */}
      <div className="relative flex min-h-0 flex-1">
        {/* Graph canvas */}
        <div className="relative min-w-0 flex-1">
          <GraphCanvas />
          <LoadingOverlay loading={loading} />
          <SeverityLegend />
        </div>

        {/* Detail panel (conditionally rendered) */}
        {selectedNodeId && <DetailPanel />}
      </div>
    </div>
  );
}
