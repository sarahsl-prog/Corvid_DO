/**
 * Loading overlay shown on the graph canvas during analysis.
 */

import { Loader2 } from "lucide-react";

interface LoadingOverlayProps {
  loading: boolean;
  message?: string;
}

export function LoadingOverlay({ loading, message }: LoadingOverlayProps) {
  if (!loading) return null;

  return (
    <div
      className="absolute inset-0 z-10 flex items-center justify-center bg-bg-primary/80"
      data-testid="loading-overlay"
    >
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="h-10 w-10 animate-spin text-accent" />
        <span className="text-sm text-text-secondary">
          {message ?? "Analyzing IOCs..."}
        </span>
      </div>
    </div>
  );
}
