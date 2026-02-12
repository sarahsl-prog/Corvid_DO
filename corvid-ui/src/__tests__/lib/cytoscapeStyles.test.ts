import { describe, it, expect } from "vitest";
import { getCytoscapeStyles } from "../../lib/cytoscapeStyles.ts";

describe("getCytoscapeStyles", () => {
  it("returns a non-empty stylesheet array", () => {
    const styles = getCytoscapeStyles();
    expect(Array.isArray(styles)).toBe(true);
    expect(styles.length).toBeGreaterThan(0);
  });

  it("includes IOC node selector", () => {
    const styles = getCytoscapeStyles();
    const iocStyle = styles.find((s) => s.selector === "node[nodeType = 'ioc']");
    expect(iocStyle).toBeDefined();
    expect(iocStyle!.style.shape).toBe("round-rectangle");
  });

  it("includes CVE node selector with diamond shape", () => {
    const styles = getCytoscapeStyles();
    const cveStyle = styles.find((s) => s.selector === "node[nodeType = 'cve']");
    expect(cveStyle).toBeDefined();
    expect(cveStyle!.style.shape).toBe("diamond");
  });

  it("includes MITRE node selector with hexagon shape", () => {
    const styles = getCytoscapeStyles();
    const mitreStyle = styles.find((s) => s.selector === "node[nodeType = 'mitre']");
    expect(mitreStyle).toBeDefined();
    expect(mitreStyle!.style.shape).toBe("hexagon");
  });

  it("includes edge selectors with different styles per type", () => {
    const styles = getCytoscapeStyles();
    const cveEdge = styles.find((s) => s.selector === "edge[edgeType = 'has_cve']");
    const mitreEdge = styles.find((s) => s.selector === "edge[edgeType = 'uses_technique']");
    const relatedEdge = styles.find((s) => s.selector === "edge[edgeType = 'related_ioc']");

    expect(cveEdge).toBeDefined();
    expect(mitreEdge).toBeDefined();
    expect(relatedEdge).toBeDefined();
    expect(relatedEdge!.style["line-style"]).toBe("dashed");
  });
});
