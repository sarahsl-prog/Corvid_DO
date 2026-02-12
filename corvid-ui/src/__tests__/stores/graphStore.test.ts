import { describe, it, expect, beforeEach } from "vitest";
import { useGraphStore } from "../../stores/graphStore.ts";
import type { CyNode, CyEdge } from "../../types/graph.ts";

// Reset store between tests
beforeEach(() => {
  useGraphStore.setState({
    nodes: [],
    edges: [],
    selectedNodeId: null,
    activeLayout: "dagre",
  });
});

const nodeA: CyNode = { data: { id: "a", label: "A", nodeType: "ioc" } };
const nodeB: CyNode = { data: { id: "b", label: "B", nodeType: "cve" } };
const edgeAB: CyEdge = { data: { source: "a", target: "b", edgeType: "has_cve" } };

describe("graphStore", () => {
  it("starts with empty state", () => {
    const state = useGraphStore.getState();
    expect(state.nodes).toHaveLength(0);
    expect(state.edges).toHaveLength(0);
    expect(state.selectedNodeId).toBeNull();
    expect(state.activeLayout).toBe("dagre");
  });

  it("addElements adds nodes and edges", () => {
    useGraphStore.getState().addElements([nodeA, nodeB], [edgeAB]);
    const state = useGraphStore.getState();
    expect(state.nodes).toHaveLength(2);
    expect(state.edges).toHaveLength(1);
  });

  it("addElements deduplicates nodes by ID", () => {
    useGraphStore.getState().addElements([nodeA], []);
    useGraphStore.getState().addElements([nodeA, nodeB], []);
    expect(useGraphStore.getState().nodes).toHaveLength(2);
  });

  it("addElements preserves existing elements", () => {
    useGraphStore.getState().addElements([nodeA], []);
    useGraphStore.getState().addElements([nodeB], [edgeAB]);
    const state = useGraphStore.getState();
    expect(state.nodes).toHaveLength(2);
    expect(state.edges).toHaveLength(1);
  });

  it("addElements handles empty additions", () => {
    useGraphStore.getState().addElements([], []);
    expect(useGraphStore.getState().nodes).toHaveLength(0);
  });

  it("removeNode removes node and connected edges", () => {
    useGraphStore.getState().addElements([nodeA, nodeB], [edgeAB]);
    useGraphStore.getState().removeNode("a");
    const state = useGraphStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].data.id).toBe("b");
    expect(state.edges).toHaveLength(0); // edge connected to "a" removed
  });

  it("removeNode clears selection if removed node was selected", () => {
    useGraphStore.getState().addElements([nodeA], []);
    useGraphStore.getState().selectNode("a");
    useGraphStore.getState().removeNode("a");
    expect(useGraphStore.getState().selectedNodeId).toBeNull();
  });

  it("selectNode updates selection", () => {
    useGraphStore.getState().selectNode("test-id");
    expect(useGraphStore.getState().selectedNodeId).toBe("test-id");
  });

  it("selectNode with null deselects", () => {
    useGraphStore.getState().selectNode("test-id");
    useGraphStore.getState().selectNode(null);
    expect(useGraphStore.getState().selectedNodeId).toBeNull();
  });

  it("setLayout updates active layout", () => {
    useGraphStore.getState().setLayout("cose-bilkent");
    expect(useGraphStore.getState().activeLayout).toBe("cose-bilkent");
  });

  it("clearGraph empties everything", () => {
    useGraphStore.getState().addElements([nodeA, nodeB], [edgeAB]);
    useGraphStore.getState().selectNode("a");
    useGraphStore.getState().clearGraph();
    const state = useGraphStore.getState();
    expect(state.nodes).toHaveLength(0);
    expect(state.edges).toHaveLength(0);
    expect(state.selectedNodeId).toBeNull();
  });
});
