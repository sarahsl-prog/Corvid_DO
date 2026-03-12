/**
 * Tests for the filter store Zustand state management.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { useFilterStore } from "../../stores/filterStore";
import type { IOCType } from "../../types/api";
import type { NodeType } from "../../types/graph";

describe("filterStore", () => {
  beforeEach(() => {
    useFilterStore.setState({
      severityRange: [0, 10],
      confidenceThreshold: 0,
      iocTypes: new Set<IOCType>(),
      nodeTypes: new Set<NodeType>(),
      sources: new Set<string>(),
    });
  });

  describe("setSeverityRange", () => {
    it("updates severity range", () => {
      useFilterStore.getState().setSeverityRange([2.5, 7.5]);

      expect(useFilterStore.getState().severityRange).toEqual([2.5, 7.5]);
    });

    it("accepts identical min and max", () => {
      useFilterStore.getState().setSeverityRange([5, 5]);

      expect(useFilterStore.getState().severityRange).toEqual([5, 5]);
    });

    it("accepts full range 0-10", () => {
      useFilterStore.getState().setSeverityRange([0, 10]);

      expect(useFilterStore.getState().severityRange).toEqual([0, 10]);
    });

    it("accepts partial lower range", () => {
      useFilterStore.getState().setSeverityRange([0, 3]);

      expect(useFilterStore.getState().severityRange).toEqual([0, 3]);
    });

    it("accepts partial upper range", () => {
      useFilterStore.getState().setSeverityRange([7, 10]);

      expect(useFilterStore.getState().severityRange).toEqual([7, 10]);
    });
  });

  describe("setConfidenceThreshold", () => {
    it("updates confidence threshold", () => {
      useFilterStore.getState().setConfidenceThreshold(0.75);

      expect(useFilterStore.getState().confidenceThreshold).toBe(0.75);
    });

    it("accepts 0 (no threshold)", () => {
      useFilterStore.getState().setConfidenceThreshold(0);

      expect(useFilterStore.getState().confidenceThreshold).toBe(0);
    });

    it("accepts 1 (maximum threshold)", () => {
      useFilterStore.getState().setConfidenceThreshold(1);

      expect(useFilterStore.getState().confidenceThreshold).toBe(1);
    });
  });

  describe("toggleIOCType", () => {
    it("adds IOC type when not present", () => {
      useFilterStore.getState().toggleIOCType("ip");

      expect(useFilterStore.getState().iocTypes.has("ip")).toBe(true);
    });

    it("removes IOC type when already present", () => {
      useFilterStore.getState().toggleIOCType("ip");
      useFilterStore.getState().toggleIOCType("ip");

      expect(useFilterStore.getState().iocTypes.has("ip")).toBe(false);
    });

    it("handles multiple IOC types", () => {
      useFilterStore.getState().toggleIOCType("ip");
      useFilterStore.getState().toggleIOCType("domain");
      useFilterStore.getState().toggleIOCType("hash_md5");

      const types = useFilterStore.getState().iocTypes;
      expect(types.size).toBe(3);
      expect(types.has("ip")).toBe(true);
      expect(types.has("domain")).toBe(true);
      expect(types.has("hash_md5")).toBe(true);
    });

    it("works with all IOC types", () => {
      const allTypes: IOCType[] = [
        "ip",
        "domain",
        "url",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "email",
      ];

      allTypes.forEach((type) => {
        useFilterStore.getState().toggleIOCType(type);
      });

      const types = useFilterStore.getState().iocTypes;
      expect(types.size).toBe(7);
      allTypes.forEach((type) => {
        expect(types.has(type)).toBe(true);
      });
    });
  });

  describe("toggleNodeType", () => {
    it("adds node type when not present", () => {
      useFilterStore.getState().toggleNodeType("ioc");

      expect(useFilterStore.getState().nodeTypes.has("ioc")).toBe(true);
    });

    it("removes node type when already present", () => {
      useFilterStore.getState().toggleNodeType("cve");
      useFilterStore.getState().toggleNodeType("cve");

      expect(useFilterStore.getState().nodeTypes.has("cve")).toBe(false);
    });

    it("handles all node types", () => {
      const allNodeTypes: NodeType[] = ["ioc", "cve", "mitre"];

      allNodeTypes.forEach((type) => {
        useFilterStore.getState().toggleNodeType(type);
      });

      const types = useFilterStore.getState().nodeTypes;
      expect(types.size).toBe(3);
    });
  });

  describe("toggleSource", () => {
    it("adds source when not present", () => {
      useFilterStore.getState().toggleSource("abuseipdb");

      expect(useFilterStore.getState().sources.has("abuseipdb")).toBe(true);
    });

    it("removes source when already present", () => {
      useFilterStore.getState().toggleSource("urlhaus");
      useFilterStore.getState().toggleSource("urlhaus");

      expect(useFilterStore.getState().sources.has("urlhaus")).toBe(false);
    });

    it("handles multiple sources", () => {
      useFilterStore.getState().toggleSource("abuseipdb");
      useFilterStore.getState().toggleSource("urlhaus");
      useFilterStore.getState().toggleSource("nvd");

      const sources = useFilterStore.getState().sources;
      expect(sources.size).toBe(3);
    });
  });

  describe("resetFilters", () => {
    it("resets all filters to defaults", () => {
      // Set up various filters
      useFilterStore.getState().setSeverityRange([2, 8]);
      useFilterStore.getState().setConfidenceThreshold(0.5);
      useFilterStore.getState().toggleIOCType("ip");
      useFilterStore.getState().toggleNodeType("cve");
      useFilterStore.getState().toggleSource("abuseipdb");

      // Reset
      useFilterStore.getState().resetFilters();

      // Verify defaults
      const state = useFilterStore.getState();
      expect(state.severityRange).toEqual([0, 10]);
      expect(state.confidenceThreshold).toBe(0);
      expect(state.iocTypes.size).toBe(0);
      expect(state.nodeTypes.size).toBe(0);
      expect(state.sources.size).toBe(0);
    });

    it("clears only active filters", () => {
      // Set specific filters
      useFilterStore.getState().toggleIOCType("domain");
      useFilterStore.getState().toggleNodeType("mitre");

      // Reset
      useFilterStore.getState().resetFilters();

      const state = useFilterStore.getState();
      expect(state.iocTypes.has("domain")).toBe(false);
      expect(state.nodeTypes.has("mitre")).toBe(false);
      expect(state.iocTypes.has("ip")).toBe(false);
    });

    it("works when no filters are active", () => {
      // Reset without setting any filters
      useFilterStore.getState().resetFilters();

      const state = useFilterStore.getState();
      expect(state.severityRange).toEqual([0, 10]);
      expect(state.iocTypes.size).toBe(0);
    });
  });

  describe("combined filter operations", () => {
    it("maintains independent states for different filter types", () => {
      // Set multiple filters
      useFilterStore.getState().setSeverityRange([3, 7]);
      useFilterStore.getState().toggleIOCType("ip");
      useFilterStore.getState().toggleIOCType("domain");
      useFilterStore.getState().toggleNodeType("cve");

      const state = useFilterStore.getState();
      expect(state.severityRange).toEqual([3, 7]);
      expect(state.iocTypes.size).toBe(2);
      expect(state.nodeTypes.size).toBe(1);
      expect(state.sources.size).toBe(0);
    });

    it("allows partial reset of only specific filters", () => {
      // Set up filters
      useFilterStore.getState().setSeverityRange([2, 8]);
      useFilterStore.getState().toggleIOCType("ip");
      useFilterStore.getState().toggleNodeType("cve");

      // Reset only severity manually
      useFilterStore.getState().setSeverityRange([0, 10]);

      const state = useFilterStore.getState();
      expect(state.severityRange).toEqual([0, 10]);
      expect(state.iocTypes.has("ip")).toBe(true);
      expect(state.nodeTypes.has("cve")).toBe(true);
    });
  });
});
