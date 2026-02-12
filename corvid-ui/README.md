# Corvid Investigation Board

Graph-based threat intelligence workspace for SOC analysts. Part of the [Corvid](../README.md) platform.

## Quick Start

```bash
npm install
npm run dev        # Dev server at http://localhost:5173 (proxies /api → localhost:8000)
```

Requires the Corvid API backend running on port 8000.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server with HMR |
| `npm run build` | Type-check (`tsc -b`) + production build |
| `npm run lint` | ESLint check |
| `npm test` | Run all tests (Vitest, single run) |
| `npm run test:watch` | Run tests in watch mode |
| `npm run preview` | Preview production build |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | React 19 + TypeScript 5.9 |
| Build | Vite 7 |
| Graph engine | Cytoscape.js + dagre/cose-bilkent layouts |
| State | Zustand 5 |
| Styling | Tailwind CSS v4 (dark theme) |
| HTTP | Axios |
| Testing | Vitest + React Testing Library |

## Architecture

```
IOCInputBar → useAnalysis hook → POST /api/v1/analyses/analyze
                                        ↓
                              graphTransforms.ts (API → Cytoscape elements)
                                        ↓
                              graphStore (Zustand) → GraphCanvas (Cytoscape.js)
                                        ↓
                              Click node → DetailPanel (CVECard, MitreOverlay, EnrichmentCard)
                              Click "Expand" → useEnrichment → new nodes animated into graph
```

## Directory Layout

```
src/
├── components/         # UI components
│   ├── InvestigationBoard.tsx   # Main layout shell
│   ├── GraphCanvas.tsx          # Cytoscape wrapper
│   ├── IOCInputBar.tsx          # IOC submission form (auto-type detection)
│   ├── DetailPanel.tsx          # Side panel for selected node
│   ├── CVECard.tsx              # CVE detail card
│   ├── MitreOverlay.tsx         # MITRE ATT&CK technique card
│   ├── EnrichmentCard.tsx       # Per-source enrichment summary
│   ├── SeverityGauge.tsx        # Color-coded 0-10 gauge
│   ├── SeverityLegend.tsx       # Color scale reference
│   └── LoadingOverlay.tsx       # Loading spinner
├── hooks/              # API integration hooks
├── stores/             # Zustand state management
├── lib/                # Utilities (api client, graph transforms, styles, constants)
├── types/              # TypeScript types mirroring backend Pydantic models
└── __tests__/          # 91 unit/component tests
```

## Testing

91 tests across 11 test files covering components, stores, and library utilities.

```bash
npm test                              # All tests
npx vitest run src/__tests__/components/  # Component tests only
npx vitest run src/__tests__/stores/      # Store tests only
npx vitest run src/__tests__/lib/         # Library tests only
npx vitest --watch                        # Watch mode
npx vitest run --coverage                 # With coverage
```

## Implementation Status

- [x] **Phase UI-1**: Project scaffold, Cytoscape graph rendering, dark theme
- [x] **Phase UI-2**: API integration, IOC submission, graph transforms
- [x] **Phase UI-3**: Detail panel, CVE/MITRE/enrichment cards, expand & enrich
- [ ] **Phase UI-4**: Filters, layout switching, keyboard shortcuts, polish
- [ ] **Phase UI-5**: Docker integration, nginx proxy, production deployment

See [docs/UI_DESIGN.md](../docs/UI_DESIGN.md) for the full design specification.
