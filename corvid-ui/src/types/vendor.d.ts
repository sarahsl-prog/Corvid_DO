/** Missing type declarations for untyped packages. */
declare module "react-cytoscapejs" {
  import type { Core, ElementsDefinition, Stylesheet, CytoscapeOptions } from "cytoscape";
  import type { Component } from "react";

  interface CytoscapeComponentProps {
    elements: ElementsDefinition;
    stylesheet?: Stylesheet[];
    style?: React.CSSProperties;
    cy?: (cy: Core) => void;
    minZoom?: number;
    maxZoom?: number;
    wheelSensitivity?: number;
    layout?: CytoscapeOptions["layout"];
    [key: string]: unknown;
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {
    static normalizeElements(
      elements: ElementsDefinition,
    ): ElementsDefinition;
  }
}

declare module "cytoscape-cose-bilkent" {
  import type { use } from "cytoscape";
  const ext: Parameters<typeof use>[0];
  export default ext;
}
