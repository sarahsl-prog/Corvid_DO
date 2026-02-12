# Corvid Investigation Board — UI Design & Implementation Plan

> **Status**: Phases UI-1 through UI-3 implemented; UI-4 and UI-5 pending
> **Author**: Generated for DigitalOcean Hackathon
> **Last Updated**: 2026-02-12
> **Backend Dependency**: Corvid API v1 (FastAPI, Phases 1–4 complete)

---

## Table of Contents

1. [Vision & Goals](#1-vision--goals)
2. [Technology Decisions](#2-technology-decisions)
3. [Architecture](#3-architecture)
4. [Data Model & API Mapping](#4-data-model--api-mapping)
5. [Component Specification](#5-component-specification)
6. [Implementation Plan](#6-implementation-plan)
7. [Testing Strategy](#7-testing-strategy)
8. [Accessibility & Performance](#8-accessibility--performance)
9. [Deployment](#9-deployment)

---

## 1. Vision & Goals

The Corvid Investigation Board is a **graph-based threat intelligence workspace** that lets SOC analysts:

- Submit IOCs and visualize relationships (IOC → CVE → MITRE technique → related IOCs)
- Expand the graph interactively by enriching nodes on click
- Filter and highlight subgraphs by severity, IOC type, or data source
- Drill into detail panels for any node without leaving the canvas
- Track investigation history across sessions

### Design Principles

| Principle | Rationale |
|-----------|-----------|
| **Graph-first** | Threat analysis is fundamentally about relationships — a table view hides the signal |
| **Progressive disclosure** | Start with the submitted IOC; expand outward as the analyst drills in |
| **Dark theme** | Industry convention for security tooling; reduces eye strain in SOC environments |
| **Keyboard-navigable** | SOC analysts work fast — every action should be reachable without a mouse |
| **Offline-safe rendering** | No CDN dependencies; must work in air-gapped SOC labs |

---

## 2. Technology Decisions

### 2.1 Core Stack

| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| **Framework** | React | 19.x | Largest ecosystem, best Cytoscape bindings, team familiarity |
| **Language** | TypeScript | 5.9 | Type safety aligns with backend's strict Pydantic models; catches API contract drift at compile time |
| **Build tool** | Vite | 7.x | Sub-second HMR, native ESM, minimal config vs. Webpack |
| **Graph engine** | Cytoscape.js | 3.x | Purpose-built for network graphs; layout algorithms, selectors, and event system designed for this exact use case |
| **React bindings** | react-cytoscapejs | 2.x | Thin wrapper — renders Cytoscape in a React component with declarative element updates |
| **Styling** | Tailwind CSS | 4.x | Utility-first, Vite plugin integration, easy dark theme, fast iteration |
| **HTTP client** | Axios | 1.x | Interceptors for auth/request-ID propagation, cleaner error handling than fetch |
| **State management** | Zustand | 5.x | Minimal boilerplate, works well for graph state (nodes/edges as a store); avoids Redux complexity |
| **Routing** | React Router | 7.x | If multi-page (e.g., `/investigate`, `/history`); optional for SPA |
| **Icons** | Lucide React | latest | Tree-shakeable SVG icons, consistent with security tooling aesthetics |

### 2.2 Why Cytoscape.js Over Alternatives

| Criterion | Cytoscape.js | D3.js | Sigma.js | vis.js |
|-----------|-------------|-------|----------|--------|
| **Layout algorithms** | 10+ built-in (dagre, cose, breadthfirst, concentric, grid) | Manual — must implement force layout | Limited (ForceAtlas2) | Basic (hierarchical, physics) |
| **Selector system** | CSS-like: `node[severity > 7]`, `edge[source = "abuseipdb"]` | None — manual filtering | Basic | None |
| **Expand-on-click** | Native `add()` with animation | Manual DOM manipulation | Manual | Partial |
| **Styling** | Declarative stylesheet (JSON) | Imperative (SVG attrs) | WebGL shaders | CSS-like |
| **Performance (1k nodes)** | Canvas renderer, smooth | SVG — degrades | WebGL — excellent | Canvas — good |
| **React integration** | `react-cytoscapejs` wrapper | Manual ref management | `@react-sigma/core` | `react-vis-network-graph` |
| **Learning curve** | Moderate (graph-specific API) | Steep (general-purpose) | Moderate | Low |
| **Best for** | Interactive investigation graphs | Custom visualizations | Large-scale graphs (10k+) | Quick prototypes |

**Verdict**: Cytoscape.js gives us the best ratio of built-in functionality to custom code for a graph-based investigation tool. The selector system alone saves hundreds of lines of filtering logic.

### 2.3 Why NOT a Python-Only UI (Streamlit / Gradio)

| Factor | React + Cytoscape | Streamlit + agraph |
|--------|-------------------|-------------------|
| Graph interactivity | Full (expand, filter, animate, drag, zoom) | Click events only, no expand-on-click |
| Custom node rendering | Shapes, icons, color gradients by severity | Circle/square only |
| Layout control | 10+ algorithms, switchable at runtime | Force-directed only |
| Performance | Client-side rendering, no server round-trip | Server re-render on every interaction |
| Keyboard navigation | Full control | Limited |
| Offline / air-gapped | Static bundle, no server needed for rendering | Requires running Python server |
| Production readiness | Standard SPA deployment | Demo-quality only |

### 2.4 Graph Layout Strategy

For the Corvid investigation graph, we use different Cytoscape layouts depending on context:

| Layout | When to Use | Effect |
|--------|-------------|--------|
| **`dagre`** | Default view after analysis completes | Hierarchical top-down: IOC → enrichments → CVEs → MITRE techniques |
| **`cose`** | When the graph has many cross-relationships | Organic force-directed clustering — related nodes group naturally |
| **`concentric`** | Severity-focused view | High-severity nodes in center, lower severity on outer rings |
| **`breadthfirst`** | Campaign tracing | Tree layout from root IOC — shows attack chain progression |
| **`grid`** | Bulk IOC comparison | Side-by-side IOC columns for comparing enrichment results |

---

## 3. Architecture

### 3.1 Directory Structure

```
corvid-ui/
├── public/
│   ├── index.html
│   └── favicon.svg                  # Corvid logo
├── src/
│   ├── main.tsx                     # Entrypoint
│   ├── App.tsx                      # Root component, router
│   ├── components/
│   │   ├── InvestigationBoard.tsx    # Main Cytoscape canvas
│   │   ├── GraphCanvas.tsx          # Cytoscape wrapper with layout logic
│   │   ├── DetailPanel.tsx          # Side panel for selected node
│   │   ├── IOCInputBar.tsx          # IOC submission form
│   │   ├── FilterToolbar.tsx        # Type/severity/source filters
│   │   ├── LayoutSwitcher.tsx       # Layout algorithm selector
│   │   ├── SeverityGauge.tsx        # Color-coded 0-10 gauge
│   │   ├── MitreOverlay.tsx         # MITRE technique detail card
│   │   ├── CVECard.tsx              # CVE detail with CVSS score
│   │   ├── EnrichmentCard.tsx       # Per-provider enrichment summary
│   │   ├── SeverityLegend.tsx       # Color scale reference
│   │   ├── HistoryDrawer.tsx        # Past investigation sessions
│   │   └── LoadingOverlay.tsx       # Skeleton/spinner during analysis
│   ├── hooks/
│   │   ├── useAnalysis.ts           # POST /api/v1/analyses/analyze
│   │   ├── useIOC.ts                # GET/POST IOC endpoints
│   │   ├── useEnrichment.ts         # POST /api/v1/iocs/{id}/enrich
│   │   └── useGraphLayout.ts        # Cytoscape layout management
│   ├── stores/
│   │   ├── graphStore.ts            # Zustand store: nodes, edges, selection
│   │   ├── filterStore.ts           # Active filters (type, severity range, source)
│   │   └── historyStore.ts          # Investigation session history
│   ├── lib/
│   │   ├── api.ts                   # Axios instance with base URL, interceptors
│   │   ├── graphTransforms.ts       # API response → Cytoscape elements
│   │   ├── cytoscapeStyles.ts       # Node/edge visual styles
│   │   └── constants.ts             # IOC types, severity thresholds, colors
│   ├── types/
│   │   ├── api.ts                   # TypeScript types mirroring Pydantic models
│   │   ├── graph.ts                 # Cytoscape element types
│   │   └── filters.ts               # Filter state types
│   └── __tests__/                   # Co-located test files
│       ├── components/
│       ├── hooks/
│       ├── stores/
│       └── lib/
├── e2e/
│   └── investigation.spec.ts        # Playwright E2E tests
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── postcss.config.js
├── .eslintrc.cjs
└── vitest.config.ts
```

### 3.2 Data Flow

```
User submits IOC(s) via IOCInputBar
        │
        ▼
useAnalysis hook → POST /api/v1/analyses/analyze
        │
        ▼
API returns AnalyzeResponse { analysis_id, status, results[] }
        │
        ▼
graphTransforms.ts converts results into Cytoscape elements:
  - IOC nodes (type, value, severity)
  - CVE nodes (cve_id, cvss_score)
  - MITRE nodes (technique_id, name)
  - IOC→CVE edges
  - IOC→MITRE edges
  - IOC→IOC edges (from related_iocs in enrichments)
        │
        ▼
graphStore.addElements() → Cytoscape re-renders
        │
        ▼
User clicks a node → DetailPanel shows full data
User clicks "Expand" → useEnrichment → new nodes added to graph
```

### 3.3 State Management (Zustand)

```typescript
// stores/graphStore.ts
interface GraphState {
  // Elements
  nodes: CyNode[];
  edges: CyEdge[];

  // Selection
  selectedNodeId: string | null;
  hoveredNodeId: string | null;

  // Layout
  activeLayout: LayoutName;

  // Actions
  addElements: (nodes: CyNode[], edges: CyEdge[]) => void;
  removeNode: (id: string) => void;
  selectNode: (id: string | null) => void;
  setLayout: (layout: LayoutName) => void;
  clearGraph: () => void;
}
```

---

## 4. Data Model & API Mapping

### 4.1 API Types (TypeScript mirrors of Pydantic models)

```typescript
// types/api.ts

/** Mirrors corvid.api.models.ioc.IOCType */
type IOCType = "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" | "hash_sha256" | "email";

/** Mirrors corvid.api.models.ioc.IOCCreate */
interface IOCCreate {
  type: IOCType;
  value: string;
  tags?: string[];
}

/** Mirrors corvid.api.models.analysis.AnalyzeRequest */
interface AnalyzeRequest {
  iocs: IOCCreate[];
  context?: string;
  priority?: "low" | "medium" | "high";
}

/** Mirrors corvid.api.models.analysis.AnalysisResultItem */
interface AnalysisResultItem {
  ioc: IOCCreate;
  severity: number;          // 0.0–10.0
  confidence: number;        // 0.0–1.0
  summary: string;
  related_cves: string[];    // ["CVE-2024-21762", ...]
  mitre_techniques: string[];// ["T1071.001", ...]
  enrichments: Record<string, unknown>;
  recommended_actions: string[];
}

/** Mirrors corvid.api.models.analysis.AnalyzeResponse */
interface AnalyzeResponse {
  analysis_id: string;       // UUID
  status: "completed" | "partial" | "failed";
  results: AnalysisResultItem[];
}

/** Mirrors corvid.api.models.ioc.IOCResponse */
interface IOCResponse {
  id: string;
  type: IOCType;
  value: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  severity_score: number | null;
  created_at: string;
  updated_at: string;
}
```

### 4.2 Graph Element Mapping

The `graphTransforms.ts` module converts API responses into Cytoscape elements:

```typescript
// lib/graphTransforms.ts

/** Map from AnalyzeResponse → Cytoscape elements */
function analysisToElements(response: AnalyzeResponse): { nodes: CyNode[]; edges: CyEdge[] } {
  const nodes: CyNode[] = [];
  const edges: CyEdge[] = [];

  for (const result of response.results) {
    // 1. IOC node
    const iocId = `ioc-${result.ioc.type}-${result.ioc.value}`;
    nodes.push({
      data: {
        id: iocId,
        label: result.ioc.value,
        nodeType: "ioc",
        iocType: result.ioc.type,
        severity: result.severity,
        confidence: result.confidence,
        summary: result.summary,
      },
    });

    // 2. CVE nodes + edges
    for (const cve of result.related_cves) {
      const cveId = `cve-${cve}`;
      nodes.push({
        data: { id: cveId, label: cve, nodeType: "cve" },
      });
      edges.push({
        data: { source: iocId, target: cveId, edgeType: "has_cve" },
      });
    }

    // 3. MITRE technique nodes + edges
    for (const technique of result.mitre_techniques) {
      const mitreId = `mitre-${technique}`;
      nodes.push({
        data: { id: mitreId, label: technique, nodeType: "mitre" },
      });
      edges.push({
        data: { source: iocId, target: mitreId, edgeType: "uses_technique" },
      });
    }
  }

  return { nodes: deduplicateNodes(nodes), edges };
}
```

### 4.3 Node Visual Mapping

| Node Type | Shape | Color Logic | Size | Icon |
|-----------|-------|-------------|------|------|
| IOC (ip) | Round rectangle | Severity gradient: green (0) → yellow (5) → red (10) | 60px | `Globe` |
| IOC (domain) | Round rectangle | Same severity gradient | 60px | `Link` |
| IOC (hash_*) | Round rectangle | Same severity gradient | 60px | `FileDigit` |
| IOC (url) | Round rectangle | Same severity gradient | 60px | `ExternalLink` |
| IOC (email) | Round rectangle | Same severity gradient | 60px | `Mail` |
| CVE | Diamond | CVSS gradient: same scale as severity | 45px | `ShieldAlert` |
| MITRE Technique | Hexagon | Tactic color (TA-based palette) | 45px | `Crosshair` |
| Related IOC | Round rectangle (dashed border) | Grey until enriched | 50px | (same as IOC type) |

### 4.4 Edge Visual Mapping

| Edge Type | Style | Color | Label |
|-----------|-------|-------|-------|
| `has_cve` | Solid | `#f59e0b` (amber) | — |
| `uses_technique` | Solid | `#8b5cf6` (violet) | — |
| `related_ioc` | Dashed | `#6b7280` (grey) | "related" |
| `enriched_by` | Dotted | `#3b82f6` (blue) | source name |

---

## 5. Component Specification

### 5.1 InvestigationBoard (Main Layout)

```
┌──────────────────────────────────────────────────────────┐
│  IOCInputBar                          [Layout] [Filters] │
├──────────────────────────────────┬───────────────────────┤
│                                  │                       │
│                                  │    DetailPanel        │
│        GraphCanvas               │    (selected node)    │
│        (Cytoscape)               │                       │
│                                  │    - Summary          │
│                                  │    - Severity gauge   │
│                                  │    - Enrichment cards │
│                                  │    - CVE list         │
│                                  │    - MITRE techniques │
│                                  │    - Actions          │
│                                  │                       │
├──────────────────────────────────┴───────────────────────┤
│  SeverityLegend                              HistoryTab  │
└──────────────────────────────────────────────────────────┘
```

- **Canvas area**: 70% width, full remaining height
- **Detail panel**: 30% width, collapsible, slides in on node selection
- **Input bar**: Fixed top, always visible
- **Legend**: Fixed bottom-left overlay on canvas

### 5.2 IOCInputBar

**Inputs**:
- IOC value (text input with auto-type-detection via `detect_ioc_type` logic mirrored client-side)
- IOC type (dropdown, auto-selected but overridable)
- Context (expandable textarea, optional)
- Priority (radio: low / medium / high)
- "Analyze" button (primary CTA)

**Behavior**:
- Supports paste of multiple IOCs (one per line) — auto-splits into batch
- Validates format client-side before submission (mirrors backend `_IOC_PATTERNS`)
- Debounced type detection on keystroke
- Disabled state with spinner while analysis is in flight

### 5.3 DetailPanel

**Sections** (collapsible accordion):

1. **Header**: IOC value + type badge + severity gauge + confidence badge
2. **Summary**: Agent-generated text summary
3. **Enrichments**: One `EnrichmentCard` per source (AbuseIPDB, URLhaus, NVD)
4. **Related CVEs**: List of `CVECard` components with CVSS scores
5. **MITRE ATT&CK**: List of technique IDs with names, linked to attack.mitre.org
6. **Recommended Actions**: Checklist (checkable for SOC workflow tracking)
7. **Raw Data**: Collapsible JSON viewer for full API response

### 5.4 FilterToolbar

**Filter controls**:

| Filter | Type | Effect on Graph |
|--------|------|-----------------|
| IOC Type | Multi-select checkboxes | Hide/show nodes by `iocType` |
| Severity Range | Dual-handle slider (0–10) | Fade nodes outside range |
| Confidence Threshold | Single slider (0–1) | Fade nodes below threshold |
| Data Source | Multi-select (AbuseIPDB, URLhaus, NVD) | Highlight edges from selected sources |
| Node Type | Checkboxes (IOC, CVE, MITRE) | Hide/show by `nodeType` |

Filters apply via Cytoscape selectors — no re-render, instant feedback.

---

## 6. Implementation Plan

### Phase UI-1: Project Scaffolding & Core Canvas (Days 1–2)

**Goal**: Render a Cytoscape graph from hardcoded data; establish project structure.

| Task | Details | Files |
|------|---------|-------|
| 1.1 | Initialize Vite + React + TypeScript project | `package.json`, `vite.config.ts`, `tsconfig.json` |
| 1.2 | Install dependencies: `cytoscape`, `react-cytoscapejs`, `tailwindcss`, `zustand`, `axios`, `lucide-react` | `package.json` |
| 1.3 | Configure Tailwind with dark theme defaults | `tailwind.config.ts`, `src/index.css` |
| 1.4 | Create TypeScript API types mirroring Pydantic models | `src/types/api.ts` |
| 1.5 | Create Cytoscape graph types | `src/types/graph.ts` |
| 1.6 | Build `cytoscapeStyles.ts` — node/edge style declarations | `src/lib/cytoscapeStyles.ts` |
| 1.7 | Build `GraphCanvas.tsx` — Cytoscape wrapper with layout prop | `src/components/GraphCanvas.tsx` |
| 1.8 | Build `graphStore.ts` — Zustand store for nodes/edges/selection | `src/stores/graphStore.ts` |
| 1.9 | Build `InvestigationBoard.tsx` — main layout shell | `src/components/InvestigationBoard.tsx` |
| 1.10 | Render a hardcoded 5-node graph to verify Cytoscape works | `src/App.tsx` |

**Exit criteria**: A dark-themed page renders a Cytoscape graph with IOC, CVE, and MITRE nodes. Nodes are styled by type. Clicking a node logs its ID to console.

### Phase UI-2: API Integration & IOC Submission (Days 3–4)

**Goal**: Connect to the Corvid API; submit IOCs and render real analysis results.

| Task | Details | Files |
|------|---------|-------|
| 2.1 | Build `api.ts` — Axios instance with `VITE_API_BASE_URL` | `src/lib/api.ts` |
| 2.2 | Build `useAnalysis.ts` hook — `POST /api/v1/analyses/analyze` | `src/hooks/useAnalysis.ts` |
| 2.3 | Build `useIOC.ts` hook — `GET/POST /api/v1/iocs/` | `src/hooks/useIOC.ts` |
| 2.4 | Build `graphTransforms.ts` — `AnalyzeResponse → CyElements` | `src/lib/graphTransforms.ts` |
| 2.5 | Build `IOCInputBar.tsx` — form with type detection, validation, submit | `src/components/IOCInputBar.tsx` |
| 2.6 | Build `LoadingOverlay.tsx` — skeleton state during analysis | `src/components/LoadingOverlay.tsx` |
| 2.7 | Wire IOCInputBar → useAnalysis → graphTransforms → graphStore → GraphCanvas | `src/components/InvestigationBoard.tsx` |
| 2.8 | Build `constants.ts` — IOC type regex patterns (mirrored from backend) | `src/lib/constants.ts` |
| 2.9 | Add CORS proxy config to Vite dev server | `vite.config.ts` |

**Exit criteria**: Typing an IP into the input bar and clicking "Analyze" calls the real API, returns results, and renders a graph with the IOC, its CVEs, and MITRE techniques as nodes.

### Phase UI-3: Detail Panel & Node Interaction (Days 5–6)

**Goal**: Click any node to see full details; expand nodes by fetching more data.

| Task | Details | Files |
|------|---------|-------|
| 3.1 | Build `DetailPanel.tsx` — collapsible side panel | `src/components/DetailPanel.tsx` |
| 3.2 | Build `SeverityGauge.tsx` — color-coded 0-10 arc | `src/components/SeverityGauge.tsx` |
| 3.3 | Build `CVECard.tsx` — CVE ID, CVSS score, description, NVD link | `src/components/CVECard.tsx` |
| 3.4 | Build `MitreOverlay.tsx` — technique name, tactics, MITRE link | `src/components/MitreOverlay.tsx` |
| 3.5 | Build `EnrichmentCard.tsx` — per-source summary card | `src/components/EnrichmentCard.tsx` |
| 3.6 | Wire node click → `selectNode()` → DetailPanel renders data | Wiring in `InvestigationBoard.tsx` |
| 3.7 | Build `useEnrichment.ts` hook — `POST /api/v1/iocs/{id}/enrich` | `src/hooks/useEnrichment.ts` |
| 3.8 | Add "Expand" button in DetailPanel → fetches enrichment → adds new nodes | `src/components/DetailPanel.tsx` |
| 3.9 | Animate new nodes entering the graph (Cytoscape `eles.animate()`) | `src/components/GraphCanvas.tsx` |

**Exit criteria**: Clicking an IOC node opens a detail panel with severity gauge, summary, CVE cards, MITRE cards, and enrichment cards. Clicking "Expand" fetches new data and animates new nodes into the graph.

### Phase UI-4: Filters, Layouts & Polish (Days 7–8)

**Goal**: Full filter system, layout switching, keyboard navigation, and visual polish.

| Task | Details | Files |
|------|---------|-------|
| 4.1 | Build `filterStore.ts` — Zustand store for filter state | `src/stores/filterStore.ts` |
| 4.2 | Build `FilterToolbar.tsx` — severity slider, type checkboxes, source multi-select | `src/components/FilterToolbar.tsx` |
| 4.3 | Apply filters via Cytoscape selectors (no re-render) | `src/components/GraphCanvas.tsx` |
| 4.4 | Build `LayoutSwitcher.tsx` — dropdown/toggle for layout algorithms | `src/components/LayoutSwitcher.tsx` |
| 4.5 | Build `useGraphLayout.ts` — layout run/animate logic | `src/hooks/useGraphLayout.ts` |
| 4.6 | Build `SeverityLegend.tsx` — fixed overlay on canvas | `src/components/SeverityLegend.tsx` |
| 4.7 | Build `HistoryDrawer.tsx` — past investigations from `historyStore` | `src/components/HistoryDrawer.tsx` |
| 4.8 | Add keyboard shortcuts: `Escape` (deselect), `Delete` (remove node), `F` (fit graph), `1-5` (switch layout) | `src/components/InvestigationBoard.tsx` |
| 4.9 | Add right-click context menu on nodes (expand, remove, copy value) | `src/components/GraphCanvas.tsx` |
| 4.10 | Responsive layout for narrower viewports (collapse detail panel to bottom sheet) | Tailwind responsive classes |
| 4.11 | Micro-animations: node hover glow, edge highlight on path, selection ring | `src/lib/cytoscapeStyles.ts` |

**Exit criteria**: Full filter system works, layout can be switched between 5 algorithms, keyboard shortcuts are functional, and the UI is polished with dark theme, hover effects, and responsive behavior.

### Phase UI-5: Integration & Production (Days 9–10)

**Goal**: Docker integration, production build, and final deployment.

| Task | Details | Files |
|------|---------|-------|
| 5.1 | Add `Dockerfile` for frontend (multi-stage: build + nginx) | `corvid-ui/Dockerfile` |
| 5.2 | Add `corvid-ui` service to `docker-compose.yml` | `docker-compose.yml` |
| 5.3 | Configure nginx to proxy `/api/` to backend container | `corvid-ui/nginx.conf` |
| 5.4 | Update `deploy/do-app-spec.yaml` with frontend static site component | `deploy/do-app-spec.yaml` |
| 5.5 | Production build optimizations: code splitting, tree shaking, asset hashing | `vite.config.ts` |
| 5.6 | Add `VITE_API_BASE_URL` env var injection at build time | `src/lib/api.ts` |
| 5.7 | Write end-to-end smoke test: submit IOC → verify graph renders | `e2e/investigation.spec.ts` |

**Exit criteria**: `docker compose up` starts both backend and frontend. Navigating to `http://localhost:3000` shows the Investigation Board. Submitting an IOC renders a graph with real API data.

---

## 7. Testing Strategy

### 7.1 Testing Pyramid

```
         ┌─────────┐
         │   E2E   │  2–3 tests (Playwright)
         │ Browser │  Full user flows
         ├─────────┤
         │  Integ  │  8–10 tests (Vitest + MSW)
         │  API    │  Hook → mock API → store updates
         ├─────────┤
         │  Unit   │  40–50 tests (Vitest + RTL)
         │  Comps  │  Component rendering, store logic
         └─────────┘
```

### 7.2 Test Tooling

| Tool | Purpose |
|------|---------|
| **Vitest** | Unit and integration test runner (Vite-native, Jest-compatible API) |
| **React Testing Library (RTL)** | Component testing — renders components, simulates user events |
| **Mock Service Worker (MSW)** | HTTP-level API mocking — intercepts Axios requests with realistic responses |
| **Playwright** | End-to-end browser tests — real browser, real rendering |
| **@testing-library/user-event** | Realistic user interactions (typing, clicking, keyboard) |

### 7.3 Unit Tests

#### Components (`src/__tests__/components/`)

| Test File | Tests | What It Verifies |
|-----------|-------|------------------|
| `IOCInputBar.test.tsx` | 8 | Renders form fields; auto-detects IOC type on paste; validates format; disables during submit; calls onSubmit with correct payload; handles multi-line paste; shows validation error for bad input; clears on successful submit |
| `GraphCanvas.test.tsx` | 6 | Renders Cytoscape instance; displays correct node count; applies styles by node type; calls onNodeSelect on click; re-renders when elements change; applies layout on prop change |
| `DetailPanel.test.tsx` | 7 | Renders when node selected; shows severity gauge; shows summary text; renders CVE cards; renders MITRE cards; renders enrichment cards; hides when no selection |
| `SeverityGauge.test.tsx` | 4 | Renders 0 (green); renders 5 (yellow); renders 10 (red); handles null severity |
| `CVECard.test.tsx` | 3 | Renders CVE ID and CVSS score; links to NVD; handles missing CVSS |
| `MitreOverlay.test.tsx` | 3 | Renders technique ID and name; links to attack.mitre.org; renders tactic tags |
| `EnrichmentCard.test.tsx` | 3 | Renders source name and summary; handles empty enrichment; renders key-value data |
| `FilterToolbar.test.tsx` | 5 | Renders all filter controls; severity slider updates store; type checkboxes toggle; source multi-select works; "Reset" clears all filters |
| `LayoutSwitcher.test.tsx` | 3 | Renders layout options; switches layout on click; highlights active layout |
| `LoadingOverlay.test.tsx` | 2 | Shows spinner when loading; hides when not loading |

**Subtotal: ~44 unit tests (components)**

#### Stores (`src/__tests__/stores/`)

| Test File | Tests | What It Verifies |
|-----------|-------|------------------|
| `graphStore.test.ts` | 8 | `addElements` adds nodes and edges; `removeNode` removes node and connected edges; `selectNode` updates selection; `setLayout` updates layout; `clearGraph` empties everything; deduplicates nodes by ID; handles empty additions; preserves existing elements on add |
| `filterStore.test.ts` | 5 | Sets severity range; toggles IOC type filter; toggles source filter; resets all filters; computes filtered selector string |
| `historyStore.test.ts` | 3 | Saves investigation session; loads past session; limits history to N entries |

**Subtotal: ~16 unit tests (stores)**

#### Library (`src/__tests__/lib/`)

| Test File | Tests | What It Verifies |
|-----------|-------|------------------|
| `graphTransforms.test.ts` | 10 | Converts single IOC result to node; creates CVE nodes from related_cves; creates MITRE nodes from mitre_techniques; creates IOC→CVE edges; creates IOC→MITRE edges; deduplicates shared CVEs across IOCs; handles empty results; handles missing optional fields; preserves severity/confidence on IOC node data; generates deterministic node IDs |
| `constants.test.ts` | 7 | Detects IP type; detects domain type; detects URL type; detects MD5 hash; detects SHA256 hash; detects email type; returns null for unknown format |
| `cytoscapeStyles.test.ts` | 4 | Returns style array; IOC node style uses severity color; CVE node uses diamond shape; edge styles differ by type |

**Subtotal: ~21 unit tests (lib)**

### 7.4 Integration Tests

Integration tests verify that hooks correctly interact with the API (mocked via MSW) and update Zustand stores.

| Test File | Tests | What It Verifies |
|-----------|-------|------------------|
| `useAnalysis.test.ts` | 4 | Calls POST /analyses/analyze with correct body; returns parsed AnalyzeResponse; sets loading state during request; handles API error (500) gracefully |
| `useIOC.test.ts` | 3 | Fetches IOC list with pagination; creates IOC via POST; handles 422 validation error |
| `useEnrichment.test.ts` | 3 | Calls POST /iocs/{id}/enrich; returns enrichment result; handles timeout |

**Subtotal: ~10 integration tests**

### 7.5 End-to-End Tests (Playwright)

| Test File | Tests | What It Verifies |
|-----------|-------|------------------|
| `investigation.spec.ts` | 3 | **Full investigation flow**: type IP → click Analyze → graph renders with nodes → click IOC node → detail panel opens with severity and summary. **Multi-IOC batch**: paste 3 IOCs → Analyze → 3 IOC nodes appear. **Filter interaction**: submit IOC → apply severity filter → low-severity nodes fade. |

**Subtotal: 3 E2E tests**

### 7.6 MSW Mock Setup

```typescript
// src/__tests__/mocks/handlers.ts
import { http, HttpResponse } from "msw";

const MOCK_ANALYZE_RESPONSE: AnalyzeResponse = {
  analysis_id: "550e8400-e29b-41d4-a716-446655440000",
  status: "completed",
  results: [
    {
      ioc: { type: "ip", value: "203.0.113.42" },
      severity: 7.8,
      confidence: 0.85,
      summary: "This IP is associated with known C2 infrastructure...",
      related_cves: ["CVE-2024-21762", "CVE-2023-44487"],
      mitre_techniques: ["T1071.001", "T1105"],
      enrichments: {
        abuseipdb: { abuse_confidence_score: 92, total_reports: 47 },
        urlhaus: { threat: "malware_download", urls_hosted: 3 },
      },
      recommended_actions: [
        "Block IP at perimeter firewall",
        "Search SIEM for historical connections to this IP",
        "Check for CVE-2024-21762 patches on exposed FortiGate devices",
      ],
    },
  ],
};

export const handlers = [
  http.post("*/api/v1/analyses/analyze", () => {
    return HttpResponse.json(MOCK_ANALYZE_RESPONSE);
  }),
  http.get("*/api/v1/iocs/", () => {
    return HttpResponse.json({ items: [], total: 0 });
  }),
  http.post("*/api/v1/iocs/:iocId/enrich", () => {
    return HttpResponse.json({ status: "enrichment_complete" });
  }),
];
```

### 7.7 Test Commands

```bash
# Unit + integration tests
npx vitest run                            # All tests, single run
npx vitest                                # Watch mode
npx vitest run --coverage                 # With coverage report
npx vitest run src/__tests__/components/  # Component tests only
npx vitest run src/__tests__/lib/         # Library tests only
npx vitest run src/__tests__/stores/      # Store tests only

# End-to-end tests (requires running backend + frontend)
npx playwright test                       # All E2E tests
npx playwright test --headed              # With visible browser
npx playwright test --ui                  # Interactive UI mode
```

### 7.8 Test Coverage Targets

| Category | Target | Rationale |
|----------|--------|-----------|
| `lib/` (transforms, constants) | 95%+ | Pure functions, easy to test exhaustively |
| `stores/` (Zustand) | 90%+ | State logic is critical for graph correctness |
| `hooks/` (API) | 85%+ | Integration points — mock at HTTP boundary |
| `components/` | 80%+ | Focus on behavior over pixel-perfect rendering |
| Overall | 85%+ | High confidence for a data-driven UI |

### 7.9 Test Summary Table

| Category | File Count | Test Count |
|----------|-----------|------------|
| Unit — Components | 10 | 44 |
| Unit — Stores | 3 | 16 |
| Unit — Lib | 3 | 21 |
| Integration — Hooks | 3 | 10 |
| E2E — Playwright | 1 | 3 |
| **Total** | **20** | **94** |

---

## 8. Accessibility & Performance

### 8.1 Accessibility (a11y)

| Requirement | Implementation |
|-------------|---------------|
| Screen reader support for graph | `aria-live` region announces node additions; `aria-label` on canvas describes graph summary |
| Keyboard navigation | `Tab` moves between IOC input, graph, and detail panel. Arrow keys navigate nodes. `Enter` selects. `Escape` deselects |
| Color contrast | All text meets WCAG AA (4.5:1) against dark background. Severity colors are supplemented with shape/icon — not color-only |
| Focus indicators | Visible focus ring on all interactive elements |
| Reduced motion | `prefers-reduced-motion` disables graph animations |

### 8.2 Performance Budgets

| Metric | Target | How |
|--------|--------|-----|
| Initial bundle size | < 250 KB gzipped | Tree-shaking, code splitting, Cytoscape loaded lazily |
| First Contentful Paint | < 1.5s | Vite's optimized build, minimal critical CSS |
| Graph render (50 nodes) | < 200ms | Cytoscape canvas renderer (not SVG) |
| Graph render (500 nodes) | < 1s | Batch element addition, `cy.startBatch()` / `cy.endBatch()` |
| Layout animation | 60 FPS | Cytoscape's built-in requestAnimationFrame loop |
| API → graph update | < 100ms after response | Direct store mutation, no intermediate re-renders |

---

## 9. Deployment

### 9.1 Docker (Development)

```dockerfile
# corvid-ui/Dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.25-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
```

```nginx
# corvid-ui/nginx.conf
server {
    listen 3000;
    root /usr/share/nginx/html;
    index index.html;

    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API calls to backend
    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 9.2 Docker Compose Addition

```yaml
# Add to existing docker-compose.yml
services:
  # ... existing postgres, redis, api services ...

  ui:
    build:
      context: ./corvid-ui
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    depends_on:
      - api
    environment:
      - VITE_API_BASE_URL=http://localhost:8000
```

### 9.3 DigitalOcean App Platform

Add a static site component to the existing `do-app-spec.yaml`:

```yaml
static_sites:
  - name: corvid-ui
    build_command: npm run build
    output_dir: dist
    source_dir: corvid-ui
    routes:
      - path: /
    envs:
      - key: VITE_API_BASE_URL
        scope: BUILD_TIME
        value: ${api.PUBLIC_URL}
```

---

## Appendix A: Color Palette

```css
:root {
  /* Background */
  --bg-primary: #0f172a;     /* slate-900 */
  --bg-secondary: #1e293b;   /* slate-800 */
  --bg-tertiary: #334155;    /* slate-700 */

  /* Text */
  --text-primary: #f1f5f9;   /* slate-100 */
  --text-secondary: #94a3b8; /* slate-400 */
  --text-muted: #64748b;     /* slate-500 */

  /* Severity gradient */
  --severity-0: #22c55e;     /* green-500 */
  --severity-3: #84cc16;     /* lime-500 */
  --severity-5: #eab308;     /* yellow-500 */
  --severity-7: #f97316;     /* orange-500 */
  --severity-9: #ef4444;     /* red-500 */
  --severity-10: #dc2626;    /* red-600 */

  /* Node types */
  --node-ioc: #3b82f6;       /* blue-500 */
  --node-cve: #f59e0b;       /* amber-500 */
  --node-mitre: #8b5cf6;     /* violet-500 */

  /* Accent */
  --accent: #06b6d4;         /* cyan-500 */
  --accent-hover: #22d3ee;   /* cyan-400 */
}
```

## Appendix B: Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Escape` | Deselect node / close detail panel |
| `Delete` / `Backspace` | Remove selected node from graph |
| `F` | Fit graph to viewport |
| `R` | Reset filters |
| `1` | Switch to dagre layout |
| `2` | Switch to cose layout |
| `3` | Switch to concentric layout |
| `4` | Switch to breadthfirst layout |
| `5` | Switch to grid layout |
| `Ctrl+Enter` | Submit IOC form |
| `Ctrl+K` | Focus IOC input bar |
| `/` | Focus IOC input bar (vim-style) |

## Appendix C: Dependencies (package.json)

See `corvid-ui/package.json` for the canonical dependency list. Key versions as of implementation:

```json
{
  "dependencies": {
    "react": "^19.2.0",
    "react-dom": "^19.2.0",
    "cytoscape": "^3.33.1",
    "cytoscape-dagre": "^2.5.0",
    "cytoscape-cose-bilkent": "^4.1.0",
    "react-cytoscapejs": "^2.0.0",
    "zustand": "^5.0.11",
    "axios": "^1.13.5",
    "lucide-react": "^0.563.0",
    "react-router-dom": "^7.13.0"
  },
  "devDependencies": {
    "@types/react": "^19.2.7",
    "@types/react-dom": "^19.2.3",
    "@vitejs/plugin-react": "^5.1.1",
    "typescript": "~5.9.3",
    "vite": "^7.3.1",
    "tailwindcss": "^4.1.18",
    "@tailwindcss/vite": "^4.1.18",
    "vitest": "^4.0.18",
    "@testing-library/react": "^16.3.2",
    "@testing-library/jest-dom": "^6.9.1",
    "@testing-library/user-event": "^14.6.1",
    "msw": "^2.12.10",
    "eslint": "^9.39.1",
    "typescript-eslint": "^8.48.0",
    "jsdom": "^28.0.0"
  }
}
```
