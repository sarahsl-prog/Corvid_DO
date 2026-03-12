/**
 * Filter toolbar — controls for filtering the graph visualization.
 *
 * Features:
 * - Severity range slider (dual-handle)
 * - Confidence threshold slider
 * - IOC type checkboxes
 * - Node type checkboxes
 * - Data source checkboxes
 * - Reset filters button
 */

import { useCallback, useEffect, useRef } from "react";
import { Filter, RotateCcw } from "lucide-react";
import { useFilterStore } from "../stores/filterStore.ts";
import { useGraphStore } from "../stores/graphStore.ts";
import type { IOCType } from "../types/api.ts";
import type { NodeType } from "../types/graph.ts";

const IOC_TYPE_LABELS: Record<IOCType, string> = {
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  hash_md5: "MD5 Hash",
  hash_sha1: "SHA1 Hash",
  hash_sha256: "SHA256 Hash",
  email: "Email",
};

const NODE_TYPE_LABELS: Record<NodeType, string> = {
  ioc: "IOC",
  cve: "CVE",
  mitre: "MITRE Technique",
};

const SOURCE_OPTIONS = ["abuseipdb", "urlhaus", "nvd"];

interface FilterToolbarProps {
  onClose?: () => void;
}

export function FilterToolbar({ onClose }: FilterToolbarProps) {
  const cyRef = useRef<ReturnType<typeof useGraphStore>["cyInstance"]>(null);

  // Filter store state
  const severityRange = useFilterStore((s) => s.severityRange);
  const confidenceThreshold = useFilterStore((s) => s.confidenceThreshold);
  const iocTypes = useFilterStore((s) => s.iocTypes);
  const nodeTypes = useFilterStore((s) => s.nodeTypes);
  const sources = useFilterStore((s) => s.sources);

  // Filter store actions
  const setSeverityRange = useFilterStore((s) => s.setSeverityRange);
  const setConfidenceThreshold = useFilterStore((s) => s.setConfidenceThreshold);
  const toggleIOCType = useFilterStore((s) => s.toggleIOCType);
  const toggleNodeType = useFilterStore((s) => s.toggleNodeType);
  const toggleSource = useFilterStore((s) => s.toggleSource);
  const resetFilters = useFilterStore((s) => s.resetFilters);

  // Get Cytoscape instance
  const cyInstance = useGraphStore((s) => s.cyInstance);
  const prevCyInstanceRef = useRef(cyInstance);

  // Apply filters to Cytoscape elements
  const applyFilters = useCallback(() => {
    if (!cyInstance) return;

    // Build selector for visible nodes
    let nodeSelector = "node";
    let hiddenCount = 0;

    // Apply node type filter
    if (nodeTypes.size > 0) {
      const typeSelectors = Array.from(nodeTypes).map((t) => `[nodeType = "${t}"]`);
      nodeSelector += typeSelectors.join(", ");
    }

    // Get all nodes
    cyInstance.nodes().forEach((node) => {
      const data = node.data();
      let isVisible = true;

      // Check node type
      if (nodeTypes.size > 0 && !nodeTypes.has(data.nodeType)) {
        isVisible = false;
      }

      // Check IOC type (only for IOC nodes)
      if (isVisible && data.nodeType === "ioc" && data.iocType && iocTypes.size > 0) {
        if (!iocTypes.has(data.iocType)) {
          isVisible = false;
        }
      }

      // Check severity range (only for IOC nodes with severity)
      if (isVisible && data.nodeType === "ioc" && data.severity !== undefined) {
        if (data.severity < severityRange[0] || data.severity > severityRange[1]) {
          isVisible = false;
        }
      }

      // Check confidence threshold (only for IOC nodes with confidence)
      if (isVisible && data.nodeType === "ioc" && data.confidence !== undefined) {
        if (data.confidence < confidenceThreshold) {
          isVisible = false;
        }
      }

      // Apply visibility
      if (isVisible) {
        node.style({ opacity: 1, "pointer-events": "auto" });
      } else {
        node.style({ opacity: 0.15, "pointer-events": "none" });
        hiddenCount++;
      }
    });

    // Apply edge visibility based on connected nodes
    cyInstance.edges().forEach((edge) => {
      const source = edge.source();
      const target = edge.target();
      const sourceOpacity = source.style("opacity") ?? 1;
      const targetOpacity = target.style("opacity") ?? 1;

      if (sourceOpacity < 0.5 || targetOpacity < 0.5) {
        edge.style({ opacity: 0.1 });
      } else {
        edge.style({ opacity: 1 });
      }
    });
  }, [cyInstance, severityRange, confidenceThreshold, iocTypes, nodeTypes, sources]);

  // Apply filters whenever filter state changes
  useEffect(() => {
    applyFilters();
  }, [applyFilters]);

  // Re-apply filters when graph changes
  useEffect(() => {
    if (cyInstance && cyInstance !== prevCyInstanceRef.current) {
      prevCyInstanceRef.current = cyInstance;
      applyFilters();
    }
  }, [cyInstance, applyFilters]);

  const handleSeverityMinChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const min = parseFloat(e.target.value);
    if (min <= severityRange[1]) {
      setSeverityRange([min, severityRange[1]]);
    }
  };

  const handleSeverityMaxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const max = parseFloat(e.target.value);
    if (max >= severityRange[0]) {
      setSeverityRange([severityRange[0], max]);
    }
  };

  const handleReset = () => {
    resetFilters();
    if (cyInstance) {
      cyInstance.nodes().style({ opacity: 1, "pointer-events": "auto" });
      cyInstance.edges().style({ opacity: 1 });
    }
  };

  const hasActiveFilters =
    severityRange[0] > 0 ||
    severityRange[1] < 10 ||
    confidenceThreshold > 0 ||
    iocTypes.size > 0 ||
    nodeTypes.size > 0 ||
    sources.size > 0;

  return (
    <div
      className="flex flex-col gap-4 p-4 bg-bg-secondary border-r border-bg-tertiary w-64 overflow-y-auto"
      data-testid="filter-toolbar"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-text-primary">
          <Filter className="h-4 w-4" />
          <span className="font-medium">Filters</span>
        </div>
        {hasActiveFilters && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1 text-xs text-accent hover:text-accent-hover transition-colors"
            title="Reset all filters"
          >
            <RotateCcw className="h-3 w-3" />
            Reset
          </button>
        )}
      </div>

      {/* Severity Range */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
          Severity Range
        </label>
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-severity-0">
            {severityRange[0].toFixed(1)}
          </span>
          <span className="text-text-muted">-</span>
          <span className="text-2xl font-bold text-severity-10">
            {severityRange[1].toFixed(1)}
          </span>
        </div>
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted w-8">Min</span>
            <input
              type="range"
              min="0"
              max="10"
              step="0.1"
              value={severityRange[0]}
              onChange={handleSeverityMinChange}
              className="flex-1 h-1.5 bg-bg-tertiary rounded-lg appearance-none cursor-pointer accent-accent"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted w-8">Max</span>
            <input
              type="range"
              min="0"
              max="10"
              step="0.1"
              value={severityRange[1]}
              onChange={handleSeverityMaxChange}
              className="flex-1 h-1.5 bg-bg-tertiary rounded-lg appearance-none cursor-pointer accent-accent"
            />
          </div>
        </div>
      </div>

      {/* Confidence Threshold */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
          Min Confidence
        </label>
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-accent">
            {(confidenceThreshold * 100).toFixed(0)}
          </span>
          <span className="text-sm text-text-muted">%</span>
        </div>
        <input
          type="range"
          min="0"
          max="1"
          step="0.05"
          value={confidenceThreshold}
          onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
          className="w-full h-1.5 bg-bg-tertiary rounded-lg appearance-none cursor-pointer accent-accent"
        />
      </div>

      {/* Node Types */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
          Node Types
        </label>
        <div className="space-y-1">
          {Object.entries(NODE_TYPE_LABELS).map(([type, label]) => (
            <label
              key={type}
              className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-bg-tertiary cursor-pointer transition-colors"
            >
              <input
                type="checkbox"
                checked={nodeTypes.has(type as NodeType)}
                onChange={() => toggleNodeType(type as NodeType)}
                className="w-4 h-4 rounded border-bg-tertiary bg-bg-tertiary text-accent focus:ring-accent"
              />
              <span className="text-sm text-text-secondary">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* IOC Types */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
          IOC Types
        </label>
        <div className="space-y-1">
          {Object.entries(IOC_TYPE_LABELS).map(([type, label]) => (
            <label
              key={type}
              className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-bg-tertiary cursor-pointer transition-colors"
            >
              <input
                type="checkbox"
                checked={iocTypes.has(type as IOCType)}
                onChange={() => toggleIOCType(type as IOCType)}
                className="w-4 h-4 rounded border-bg-tertiary bg-bg-tertiary text-accent focus:ring-accent"
              />
              <span className="text-sm text-text-secondary">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Data Sources */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
          Highlight Sources
        </label>
        <div className="space-y-1">
          {SOURCE_OPTIONS.map((source) => (
            <label
              key={source}
              className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-bg-tertiary cursor-pointer transition-colors"
            >
              <input
                type="checkbox"
                checked={sources.has(source)}
                onChange={() => toggleSource(source)}
                className="w-4 h-4 rounded border-bg-tertiary bg-bg-tertiary text-accent focus:ring-accent"
              />
              <span className="text-sm text-text-secondary capitalize">{source}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
