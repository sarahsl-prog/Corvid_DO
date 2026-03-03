/**
 * History Drawer — sidebar showing past investigation sessions.
 *
 * Features:
 * - List of saved investigations with timestamps
 * - Click to restore a past session
 * - Delete individual sessions
 * - Clear all history
 */

import { useState } from "react";
import { History, X, Trash2, RefreshCcw, Clock, ChevronRight } from "lucide-react";
import { useHistoryStore } from "../stores/historyStore.ts";
import { useGraphStore } from "../stores/graphStore.ts";

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function formatFullDate(timestamp: number): string {
  return new Date(timestamp).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function HistoryDrawer({ isOpen, onClose }: HistoryDrawerProps) {
  const [showConfirmClear, setShowConfirmClear] = useState(false);

  const sessions = useHistoryStore((s) => s.sessions);
  const loadSession = useHistoryStore((s) => s.loadSession);
  const deleteSession = useHistoryStore((s) => s.deleteSession);
  const clearHistory = useHistoryStore((s) => s.clearHistory);

  const setElements = useGraphStore((s) => ({
    nodes: s.nodes,
    edges: s.edges,
    clearGraph: s.clearGraph,
    addElements: s.addElements,
  }));

  const handleLoadSession = (id: string) => {
    const session = loadSession(id);
    if (session) {
      setElements.clearGraph();
      setElements.addElements(session.nodes, session.edges);
      onClose();
    }
  };

  const handleClearAll = () => {
    clearHistory();
    setShowConfirmClear(false);
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-full w-80 bg-bg-secondary border-l border-bg-tertiary z-50 flex flex-col shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-bg-tertiary">
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-accent" />
            <h2 className="font-semibold text-text-primary">Investigation History</h2>
          </div>
          <div className="flex items-center gap-1">
            {sessions.length > 0 && (
              <button
                onClick={() => setShowConfirmClear(true)}
                className="p-2 text-text-muted hover:text-severity-9 hover:bg-severity-9/10 rounded transition-colors"
                title="Clear all history"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            )}
            <button
              onClick={onClose}
              className="p-2 text-text-muted hover:text-text-primary hover:bg-bg-tertiary rounded transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-6">
              <Clock className="h-12 w-12 text-text-muted mb-4" />
              <h3 className="text-lg font-medium text-text-secondary mb-2">No investigations yet</h3>
              <p className="text-sm text-text-muted max-w-xs">
                Submit an IOC for analysis to start building your investigation history.
              </p>
            </div>
          ) : (
            <div className="py-2">
              {sessions.map((session, index) => (
                <div
                  key={session.id}
                  className="group px-4 py-3 hover:bg-bg-tertiary border-b border-bg-tertiary/50 last:border-b-0 transition-colors cursor-pointer"
                  onClick={() => handleLoadSession(session.id)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-text-primary truncate">
                          {session.name}
                        </span>
                        {index === 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 bg-accent/20 text-accent rounded-full">
                            Latest
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-xs text-text-muted" title={formatFullDate(session.timestamp)}>
                          {formatTimestamp(session.timestamp)}
                        </span>
                        <span className="text-xs text-text-muted">•</span>
                        <span className="text-xs text-text-muted">
                          {session.nodes.length} nodes
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteSession(session.id);
                        }}
                        className="p-1.5 text-text-muted hover:text-severity-9 hover:bg-severity-9/10 rounded transition-colors"
                        title="Delete this session"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                      <ChevronRight className="h-4 w-4 text-text-muted" />
                    </div>
                  </div>

                  {/* IOC preview */}
                  {session.results.length > 0 && (
                    <div className="mt-2 flex items-center gap-1.5">
                      <span className="text-[10px] text-text-muted uppercase tracking-wide">IOCs:</span>
                      <div className="flex gap-1.5">
                        {session.results.slice(0, 3).map((result, i) => (
                          <span
                            key={i}
                            className="text-[10px] px-1.5 py-0.5 bg-bg-tertiary text-text-secondary rounded"
                          >
                            {result.ioc.type === "ip"
                              ? result.ioc.value.split(".").slice(0, 2).join(".") + "..."
                              : result.ioc.value.slice(0, 8) + "..."}
                          </span>
                        ))}
                        {session.results.length > 3 && (
                          <span className="text-[10px] text-text-muted">
                            +{session.results.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Confirm Clear Modal */}
        {showConfirmClear && (
          <div className="absolute inset-x-0 bottom-0 bg-bg-secondary border-t border-bg-tertiary p-4 shadow-lg">
            <p className="text-sm text-text-secondary mb-3">
              Clear all {sessions.length} investigation{sessions.length !== 1 ? "s" : ""}? This cannot be undone.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setShowConfirmClear(false)}
                className="flex-1 px-3 py-2 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-tertiary rounded transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClearAll}
                className="flex-1 px-3 py-2 text-sm bg-severity-9/20 text-severity-9 hover:bg-severity-9/30 rounded transition-colors"
              >
                Clear All
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
