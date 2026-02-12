/**
 * Hook for submitting IOCs for analysis.
 */

import { useState, useCallback } from "react";
import type { AnalyzeRequest, AnalyzeResponse } from "../types/api.ts";
import { analyzeIOCs } from "../lib/api.ts";

interface UseAnalysisReturn {
  /** Submit IOCs for analysis. Returns the response on success. */
  analyze: (request: AnalyzeRequest) => Promise<AnalyzeResponse | null>;
  /** Whether an analysis is currently in flight. */
  loading: boolean;
  /** Error message from the last failed request, if any. */
  error: string | null;
  /** The most recent successful response. */
  data: AnalyzeResponse | null;
}

export function useAnalysis(): UseAnalysisReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AnalyzeResponse | null>(null);

  const analyze = useCallback(async (request: AnalyzeRequest) => {
    setLoading(true);
    setError(null);
    try {
      const response = await analyzeIOCs(request);
      setData(response);
      return response;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Analysis request failed";
      setError(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { analyze, loading, error, data };
}
