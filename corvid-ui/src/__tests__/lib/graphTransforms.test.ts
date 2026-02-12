import { describe, it, expect } from "vitest";
import {
  iocNodeId,
  cveNodeId,
  mitreNodeId,
  resultToElements,
  deduplicateNodes,
  analysisToElements,
} from "../../lib/graphTransforms.ts";
import type { AnalysisResultItem, AnalyzeResponse } from "../../types/api.ts";

const MOCK_RESULT: AnalysisResultItem = {
  ioc: { type: "ip", value: "203.0.113.42" },
  severity: 7.8,
  confidence: 0.85,
  summary: "Known C2 infrastructure",
  related_cves: ["CVE-2024-21762", "CVE-2023-44487"],
  mitre_techniques: ["T1071.001", "T1105"],
  enrichments: { abuseipdb: { score: 92 } },
  recommended_actions: ["Block IP at firewall"],
};

describe("ID generators", () => {
  it("generates deterministic IOC node IDs", () => {
    expect(iocNodeId("ip", "203.0.113.42")).toBe("ioc-ip-203.0.113.42");
  });

  it("generates deterministic CVE node IDs", () => {
    expect(cveNodeId("CVE-2024-21762")).toBe("cve-CVE-2024-21762");
  });

  it("generates deterministic MITRE node IDs", () => {
    expect(mitreNodeId("T1071.001")).toBe("mitre-T1071.001");
  });
});

describe("resultToElements", () => {
  it("creates an IOC node with correct data", () => {
    const { nodes } = resultToElements(MOCK_RESULT);
    const iocNode = nodes.find((n) => n.data.nodeType === "ioc");
    expect(iocNode).toBeDefined();
    expect(iocNode!.data.label).toBe("203.0.113.42");
    expect(iocNode!.data.severity).toBe(7.8);
    expect(iocNode!.data.confidence).toBe(0.85);
  });

  it("creates CVE nodes from related_cves", () => {
    const { nodes } = resultToElements(MOCK_RESULT);
    const cveNodes = nodes.filter((n) => n.data.nodeType === "cve");
    expect(cveNodes).toHaveLength(2);
    expect(cveNodes[0].data.label).toBe("CVE-2024-21762");
    expect(cveNodes[1].data.label).toBe("CVE-2023-44487");
  });

  it("creates MITRE nodes from mitre_techniques", () => {
    const { nodes } = resultToElements(MOCK_RESULT);
    const mitreNodes = nodes.filter((n) => n.data.nodeType === "mitre");
    expect(mitreNodes).toHaveLength(2);
    expect(mitreNodes[0].data.label).toBe("T1071.001");
  });

  it("creates IOC→CVE edges", () => {
    const { edges } = resultToElements(MOCK_RESULT);
    const cveEdges = edges.filter((e) => e.data.edgeType === "has_cve");
    expect(cveEdges).toHaveLength(2);
    expect(cveEdges[0].data.source).toBe("ioc-ip-203.0.113.42");
    expect(cveEdges[0].data.target).toBe("cve-CVE-2024-21762");
  });

  it("creates IOC→MITRE edges", () => {
    const { edges } = resultToElements(MOCK_RESULT);
    const mitreEdges = edges.filter((e) => e.data.edgeType === "uses_technique");
    expect(mitreEdges).toHaveLength(2);
  });

  it("handles empty CVE and MITRE lists", () => {
    const emptyResult: AnalysisResultItem = {
      ...MOCK_RESULT,
      related_cves: [],
      mitre_techniques: [],
    };
    const { nodes, edges } = resultToElements(emptyResult);
    expect(nodes).toHaveLength(1); // Just the IOC node
    expect(edges).toHaveLength(0);
  });

  it("preserves severity and confidence on IOC node data", () => {
    const { nodes } = resultToElements(MOCK_RESULT);
    const iocNode = nodes[0];
    expect(iocNode.data.severity).toBe(7.8);
    expect(iocNode.data.confidence).toBe(0.85);
    expect(iocNode.data.summary).toBe("Known C2 infrastructure");
  });
});

describe("deduplicateNodes", () => {
  it("removes duplicate nodes by ID", () => {
    const nodes = [
      { data: { id: "a", label: "A", nodeType: "ioc" as const } },
      { data: { id: "b", label: "B", nodeType: "cve" as const } },
      { data: { id: "a", label: "A duplicate", nodeType: "ioc" as const } },
    ];
    const result = deduplicateNodes(nodes);
    expect(result).toHaveLength(2);
    expect(result[0].data.label).toBe("A");
  });

  it("handles empty array", () => {
    expect(deduplicateNodes([])).toHaveLength(0);
  });
});

describe("analysisToElements", () => {
  it("converts a full AnalyzeResponse", () => {
    const response: AnalyzeResponse = {
      analysis_id: "test-id",
      status: "completed",
      results: [MOCK_RESULT],
    };
    const { nodes, edges } = analysisToElements(response);
    // 1 IOC + 2 CVEs + 2 MITRE = 5 nodes
    expect(nodes).toHaveLength(5);
    // 2 CVE edges + 2 MITRE edges = 4
    expect(edges).toHaveLength(4);
  });

  it("deduplicates shared CVEs across IOCs", () => {
    const result2: AnalysisResultItem = {
      ...MOCK_RESULT,
      ioc: { type: "domain", value: "evil.example.com" },
      related_cves: ["CVE-2024-21762"], // shared CVE
      mitre_techniques: [],
    };
    const response: AnalyzeResponse = {
      analysis_id: "test-id",
      status: "completed",
      results: [MOCK_RESULT, result2],
    };
    const { nodes } = analysisToElements(response);
    const cveNodes = nodes.filter((n) => n.data.nodeType === "cve");
    // CVE-2024-21762 should appear only once
    expect(cveNodes).toHaveLength(2);
  });

  it("handles empty results", () => {
    const response: AnalyzeResponse = {
      analysis_id: "test-id",
      status: "failed",
      results: [],
    };
    const { nodes, edges } = analysisToElements(response);
    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });
});
