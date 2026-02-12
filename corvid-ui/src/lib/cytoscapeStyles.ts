/**
 * Cytoscape.js stylesheet definitions for the investigation graph.
 *
 * Nodes are styled by nodeType (ioc, cve, mitre).
 * IOC nodes use severity-based color mapping.
 * Edges styled by edgeType.
 */

import type { StylesheetStyle } from "cytoscape";

/**
 * Returns the Cytoscape stylesheet array.
 * Pure function — safe to call in render.
 */
export function getCytoscapeStyles(): StylesheetStyle[] {
  return [
    // ── Base node style ──
    {
      selector: "node",
      style: {
        label: "data(label)",
        "text-valign": "bottom",
        "text-halign": "center",
        "font-size": "11px",
        color: "#f1f5f9",
        "text-outline-color": "#0f172a",
        "text-outline-width": 2,
        "text-max-width": "120px",
        "text-wrap": "ellipsis",
        width: 50,
        height: 50,
        "border-width": 2,
        "border-color": "#334155",
        "background-color": "#334155",
        "overlay-padding": "6px",
        "transition-property": "background-color, border-color, opacity",
        "transition-duration": 200,
      },
    },

    // ── IOC nodes ──
    {
      selector: "node[nodeType = 'ioc']",
      style: {
        shape: "round-rectangle",
        "background-color": "#3b82f6",
        "border-color": "#60a5fa",
        width: 60,
        height: 60,
      },
    },

    // ── CVE nodes ──
    {
      selector: "node[nodeType = 'cve']",
      style: {
        shape: "diamond",
        "background-color": "#f59e0b",
        "border-color": "#fbbf24",
        width: 45,
        height: 45,
      },
    },

    // ── MITRE technique nodes ──
    {
      selector: "node[nodeType = 'mitre']",
      style: {
        shape: "hexagon",
        "background-color": "#8b5cf6",
        "border-color": "#a78bfa",
        width: 45,
        height: 45,
      },
    },

    // ── Selected node ──
    {
      selector: "node:selected",
      style: {
        "border-width": 4,
        "border-color": "#06b6d4",
        "overlay-color": "#06b6d4",
        "overlay-opacity": 0.15,
      },
    },

    // ── Hovered node ──
    {
      selector: "node:active",
      style: {
        "overlay-color": "#06b6d4",
        "overlay-opacity": 0.1,
      },
    },

    // ── Faded nodes (filtered out) ──
    {
      selector: "node.faded",
      style: {
        opacity: 0.2,
      },
    },

    // ── Base edge style ──
    {
      selector: "edge",
      style: {
        width: 2,
        "line-color": "#475569",
        "target-arrow-color": "#475569",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.8,
        opacity: 0.7,
        "transition-property": "line-color, opacity",
        "transition-duration": 200,
      },
    },

    // ── has_cve edges ──
    {
      selector: "edge[edgeType = 'has_cve']",
      style: {
        "line-color": "#f59e0b",
        "target-arrow-color": "#f59e0b",
      },
    },

    // ── uses_technique edges ──
    {
      selector: "edge[edgeType = 'uses_technique']",
      style: {
        "line-color": "#8b5cf6",
        "target-arrow-color": "#8b5cf6",
      },
    },

    // ── related_ioc edges ──
    {
      selector: "edge[edgeType = 'related_ioc']",
      style: {
        "line-color": "#6b7280",
        "target-arrow-color": "#6b7280",
        "line-style": "dashed",
      },
    },

    // ── enriched_by edges ──
    {
      selector: "edge[edgeType = 'enriched_by']",
      style: {
        "line-color": "#3b82f6",
        "target-arrow-color": "#3b82f6",
        "line-style": "dotted",
      },
    },

    // ── Selected edge ──
    {
      selector: "edge:selected",
      style: {
        width: 3,
        opacity: 1,
      },
    },

    // ── Faded edges ──
    {
      selector: "edge.faded",
      style: {
        opacity: 0.1,
      },
    },
  ];
}
