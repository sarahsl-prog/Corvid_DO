/**
 * Hook for triggering IOC enrichment.
 */

import { useState, useCallback } from "react";
import { enrichIOC } from "../lib/api.ts";

interface UseEnrichmentReturn {
  /** Trigger enrichment for a specific IOC by database ID. */
  enrich: (iocId: string) => Promise<boolean>;
  loading: boolean;
  error: string | null;
}

export function useEnrichment(): UseEnrichmentReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const enrich = useCallback(async (iocId: string) => {
    setLoading(true);
    setError(null);
    try {
      await enrichIOC(iocId);
      return true;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Enrichment failed";
      setError(message);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  return { enrich, loading, error };
}
