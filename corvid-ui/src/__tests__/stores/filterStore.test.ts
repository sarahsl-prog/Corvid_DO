import { describe, it, expect, beforeEach } from "vitest";
import { useFilterStore } from "../../stores/filterStore.ts";

beforeEach(() => {
  useFilterStore.getState().resetFilters();
});

describe("filterStore", () => {
  it("starts with default filter values", () => {
    const state = useFilterStore.getState();
    expect(state.severityRange).toEqual([0, 10]);
    expect(state.confidenceThreshold).toBe(0);
    expect(state.iocTypes.size).toBe(0);
    expect(state.nodeTypes.size).toBe(0);
    expect(state.sources.size).toBe(0);
  });

  it("setSeverityRange updates the range", () => {
    useFilterStore.getState().setSeverityRange([3, 8]);
    expect(useFilterStore.getState().severityRange).toEqual([3, 8]);
  });

  it("setConfidenceThreshold updates threshold", () => {
    useFilterStore.getState().setConfidenceThreshold(0.7);
    expect(useFilterStore.getState().confidenceThreshold).toBe(0.7);
  });

  it("toggleIOCType adds and removes types", () => {
    useFilterStore.getState().toggleIOCType("ip");
    expect(useFilterStore.getState().iocTypes.has("ip")).toBe(true);

    useFilterStore.getState().toggleIOCType("ip");
    expect(useFilterStore.getState().iocTypes.has("ip")).toBe(false);
  });

  it("toggleNodeType adds and removes node types", () => {
    useFilterStore.getState().toggleNodeType("cve");
    expect(useFilterStore.getState().nodeTypes.has("cve")).toBe(true);

    useFilterStore.getState().toggleNodeType("cve");
    expect(useFilterStore.getState().nodeTypes.has("cve")).toBe(false);
  });

  it("toggleSource adds and removes sources", () => {
    useFilterStore.getState().toggleSource("abuseipdb");
    expect(useFilterStore.getState().sources.has("abuseipdb")).toBe(true);

    useFilterStore.getState().toggleSource("abuseipdb");
    expect(useFilterStore.getState().sources.has("abuseipdb")).toBe(false);
  });

  it("resetFilters restores all defaults", () => {
    useFilterStore.getState().setSeverityRange([5, 9]);
    useFilterStore.getState().setConfidenceThreshold(0.8);
    useFilterStore.getState().toggleIOCType("ip");
    useFilterStore.getState().toggleSource("abuseipdb");

    useFilterStore.getState().resetFilters();
    const state = useFilterStore.getState();
    expect(state.severityRange).toEqual([0, 10]);
    expect(state.confidenceThreshold).toBe(0);
    expect(state.iocTypes.size).toBe(0);
    expect(state.sources.size).toBe(0);
  });
});
