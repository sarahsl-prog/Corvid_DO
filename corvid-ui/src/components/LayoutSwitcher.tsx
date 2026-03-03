/**
 * Layout Switcher — dropdown to switch between Cytoscape layout algorithms.
 *
 * Layouts:
 * - dagre: Hierarchical top-down (default)
 * - cose-bilkent: Organic force-directed clustering
 * - concentric: Severity-focused concentric rings
 * - breadthfirst: Tree layout for attack chains
 * - grid: Side-by-side comparison
 */

import { useState, useRef } from "react";
import { LayoutGrid, ChevronDown, Check } from "lucide-react";
import { useGraphStore } from "../stores/graphStore.ts";
import type { LayoutName } from "../types/graph.ts";

interface LayoutOption {
  name: LayoutName;
  label: string;
  description: string;
  shortcut?: string;
}

const LAYOUTS: LayoutOption[] = [
  { name: "dagre", label: "Dagre", description: "Hierarchical top-down", shortcut: "1" },
  { name: "cose-bilkent", label: "COSE", description: "Organic clustering", shortcut: "2" },
  { name: "concentric", label: "Concentric", description: "Severity-focused rings", shortcut: "3" },
  { name: "breadthfirst", label: "Breadth-first", description: "Tree layout for chains", shortcut: "4" },
  { name: "grid", label: "Grid", description: "Side-by-side comparison", shortcut: "5" },
];

export function LayoutSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const activeLayout = useGraphStore((s) => s.activeLayout);
  const setLayout = useGraphStore((s) => s.setLayout);

  const handleSelect = (layout: LayoutName) => {
    setLayout(layout);
    setIsOpen(false);
  };

  const activeLabel = LAYOUTS.find((l) => l.name === activeLayout)?.label ?? "Dagre";

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-md bg-bg-secondary hover:bg-bg-tertiary text-text-primary text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-accent"
        data-testid="layout-switcher"
        aria-haspopup="listbox"
        aria-expanded={isOpen}
      >
        <LayoutGrid className="h-4 w-4 text-text-secondary" />
        <span className="hidden sm:inline">{activeLabel}</span>
        <ChevronDown
          className={`h-4 w-4 text-text-muted transition-transform ${isOpen ? "rotate-180" : ""}`}
        />
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute right-0 top-full mt-1 z-50 w-56 bg-bg-secondary border border-bg-tertiary rounded-lg shadow-lg overflow-hidden">
            <div className="px-3 py-2 border-b border-bg-tertiary">
              <span className="text-xs font-medium text-text-muted uppercase tracking-wide">
                Layout Algorithm
              </span>
            </div>
            <div role="listbox" className="py-1">
              {LAYOUTS.map((layout) => (
                <button
                  key={layout.name}
                  role="option"
                  aria-selected={layout.name === activeLayout}
                  onClick={() => handleSelect(layout.name)}
                  className={`w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-tertiary transition-colors ${
                    layout.name === activeLayout ? "bg-accent/10" : ""
                  }`}
                >
                  <div className="flex-1 text-left">
                    <div
                      className={`text-sm font-medium ${
                        layout.name === activeLayout ? "text-accent" : "text-text-primary"
                      }`}
                    >
                      {layout.label}
                    </div>
                    <div className="text-xs text-text-muted">{layout.description}</div>
                  </div>
                  {layout.name === activeLayout && (
                    <Check className="h-4 w-4 text-accent" />
                  )}
                  {layout.shortcut && layout.name !== activeLayout && (
                    <kbd className="hidden lg:inline-flex items-center px-1.5 h-5 text-[10px] font-mono text-text-muted bg-bg-tertiary rounded border border-bg-tertiary">
                      {layout.shortcut}
                    </kbd>
                  )}
                </button>
              ))}
            </div>
            <div className="px-3 py-2 border-t border-bg-tertiary bg-bg-tertiary/50">
              <div className="text-[10px] text-text-muted">
                Press <kbd className="font-mono">1-5</kbd> to switch layouts
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
