/**
 * Hook for IOC CRUD operations.
 */

import { useState, useCallback } from "react";
import type { IOCListResponse } from "../types/api.ts";
import { listIOCs } from "../lib/api.ts";

interface UseIOCReturn {
  /** Fetch paginated IOC list. */
  fetchIOCs: (skip?: number, limit?: number) => Promise<void>;
  loading: boolean;
  error: string | null;
  data: IOCListResponse | null;
}

export function useIOC(): UseIOCReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<IOCListResponse | null>(null);

  const fetchIOCs = useCallback(async (skip = 0, limit = 50) => {
    setLoading(true);
    setError(null);
    try {
      const response = await listIOCs(skip, limit);
      setData(response);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to fetch IOCs";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  return { fetchIOCs, loading, error, data };
}
