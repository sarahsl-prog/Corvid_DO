/**
 * TypeScript types mirroring the Corvid backend Pydantic models.
 *
 * Keep in sync with:
 *   corvid/api/models/ioc.py
 *   corvid/api/models/analysis.py
 */

/** Mirrors corvid.api.models.ioc.IOCType */
export type IOCType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email";

/** Mirrors corvid.api.models.ioc.IOCCreate */
export interface IOCCreate {
  type: IOCType;
  value: string;
  tags?: string[];
}

/** Mirrors corvid.api.models.ioc.IOCResponse */
export interface IOCResponse {
  id: string;
  type: IOCType;
  value: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  severity_score: number | null;
  created_at: string;
  updated_at: string;
}

/** Mirrors corvid.api.models.ioc.IOCListResponse */
export interface IOCListResponse {
  items: IOCResponse[];
  total: number;
}

/** Mirrors corvid.api.models.analysis.AnalyzeRequest */
export interface AnalyzeRequest {
  iocs: IOCCreate[];
  context?: string;
  priority?: "low" | "medium" | "high";
}

/** Mirrors corvid.api.models.analysis.AnalysisResultItem */
export interface AnalysisResultItem {
  ioc: IOCCreate;
  severity: number;
  confidence: number;
  summary: string;
  related_cves: string[];
  mitre_techniques: string[];
  enrichments: Record<string, unknown>;
  recommended_actions: string[];
}

/** Mirrors corvid.api.models.analysis.AnalyzeResponse */
export interface AnalyzeResponse {
  analysis_id: string;
  status: "completed" | "partial" | "failed";
  results: AnalysisResultItem[];
}

/** Mirrors corvid.api.models.analysis.AnalysisResponse (stored analysis) */
export interface AnalysisResponse {
  id: string;
  ioc_ids: string[];
  analysis_text: string;
  confidence: number;
  mitre_techniques: string[];
  recommended_actions: string[];
  created_at: string;
}
