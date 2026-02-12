/**
 * Axios client configured for the Corvid API.
 *
 * In development, Vite proxies /api to localhost:8000.
 * In production, VITE_API_BASE_URL points to the deployed backend.
 */

import axios from "axios";
import type {
  AnalyzeRequest,
  AnalyzeResponse,
  IOCListResponse,
  AnalysisResponse,
} from "../types/api.ts";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "",
  timeout: 60_000, // Agent analysis can take a while
  headers: {
    "Content-Type": "application/json",
  },
});

/** Submit IOCs for AI-powered analysis. */
export async function analyzeIOCs(request: AnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await apiClient.post<AnalyzeResponse>(
    "/api/v1/analyses/analyze",
    request,
  );
  return data;
}

/** List IOCs with optional pagination. */
export async function listIOCs(
  skip = 0,
  limit = 50,
): Promise<IOCListResponse> {
  const { data } = await apiClient.get<IOCListResponse>("/api/v1/iocs/", {
    params: { skip, limit },
  });
  return data;
}

/** Get a specific analysis by ID. */
export async function getAnalysis(analysisId: string): Promise<AnalysisResponse> {
  const { data } = await apiClient.get<AnalysisResponse>(
    `/api/v1/analyses/${analysisId}`,
  );
  return data;
}

/** Trigger enrichment for an IOC. */
export async function enrichIOC(iocId: string): Promise<{ status: string }> {
  const { data } = await apiClient.post<{ status: string }>(
    `/api/v1/iocs/${iocId}/enrich`,
  );
  return data;
}

export default apiClient;
