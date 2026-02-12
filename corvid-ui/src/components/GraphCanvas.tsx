/**
 * Cytoscape graph canvas — renders the investigation graph.
 *
 * Wraps react-cytoscapejs with layout management,
 * node selection events, and new-node animation.
 */

import { useRef, useEffect, useCallback } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";
import Cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import coseBilkent from "cytoscape-cose-bilkent";
import { getCytoscapeStyles } from "../lib/cytoscapeStyles.ts";
import { useGraphStore } from "../stores/graphStore.ts";
import type { LayoutName } from "../types/graph.ts";

// Register layout extensions once
Cytoscape.use(dagre);
Cytoscape.use(coseBilkent);

/** Map layout names to Cytoscape layout options. */
function getLayoutOptions(name: LayoutName): cytoscape.LayoutOptions {
  switch (name) {
    case "dagre":
      return { name: "dagre", rankDir: "TB", nodeSep: 60, rankSep: 80 } as cytoscape.LayoutOptions;
    case "cose-bilkent":
      return { name: "cose-bilkent", animate: true, animationDuration: 500 } as cytoscape.LayoutOptions;
    case "concentric":
      return {
        name: "concentric",
        concentric: (node: cytoscape.SingularElementArgument) => {
          return 10 - ((node as cytoscape.NodeSingular).data("severity") ?? 5);
        },
        levelWidth: () => 2,
      } as cytoscape.LayoutOptions;
    case "breadthfirst":
      return { name: "breadthfirst", directed: true, spacingFactor: 1.5 } as cytoscape.LayoutOptions;
    case "grid":
      return { name: "grid", rows: 3 } as cytoscape.LayoutOptions;
  }
}

export function GraphCanvas() {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const prevNodeCountRef = useRef(0);
  const { nodes, edges, activeLayout, selectNode, setCyInstance } = useGraphStore();

  // Handle Cytoscape instance creation
  const handleCy = useCallback(
    (cy: cytoscape.Core) => {
      cyRef.current = cy;
      setCyInstance(cy);

      // Node click → select
      cy.on("tap", "node", (evt) => {
        const nodeId = evt.target.id();
        selectNode(nodeId);
      });

      // Background click → deselect
      cy.on("tap", (evt) => {
        if (evt.target === cy) {
          selectNode(null);
        }
      });
    },
    [selectNode, setCyInstance],
  );

  // Re-run layout and animate new nodes when elements change
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.nodes().length === 0) return;

    const currentNodeCount = nodes.length;
    const prevNodeCount = prevNodeCountRef.current;
    prevNodeCountRef.current = currentNodeCount;

    // If new nodes were added, animate them in
    if (currentNodeCount > prevNodeCount && prevNodeCount > 0) {
      const allNodes = cy.nodes();
      const newNodes = allNodes.slice(prevNodeCount);

      if (newNodes.length > 0) {
        // Start new nodes transparent
        newNodes.style({ opacity: 0 });

        // Run layout first, then fade in
        const layout = cy.layout(getLayoutOptions(activeLayout));
        layout.on("layoutstop", () => {
          newNodes.animate(
            { style: { opacity: 1 } },
            { duration: 400, easing: "ease-in-out-cubic" },
          );
        });
        layout.run();
        return;
      }
    }

    // Default: just run layout
    const layout = cy.layout(getLayoutOptions(activeLayout));
    layout.run();
  }, [activeLayout, nodes.length, edges.length]);

  // Build ElementsDefinition for Cytoscape
  const elements = CytoscapeComponent.normalizeElements({
    nodes: nodes.map((n) => ({ data: { ...n.data } })),
    edges: edges.map((e) => ({ data: { ...e.data } })),
  });

  return (
    <div className="relative h-full w-full" data-testid="graph-canvas">
      <CytoscapeComponent
        elements={elements}
        stylesheet={getCytoscapeStyles()}
        style={{ width: "100%", height: "100%" }}
        cy={handleCy}
        minZoom={0.3}
        maxZoom={3}
        wheelSensitivity={0.3}
      />
    </div>
  );
}
