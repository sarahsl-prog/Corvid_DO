# Corvid Feature Gap Analysis

**Generated:** 2026-03-02  
**Repository:** Corvid_DO  
**Analysis Scope:** Documentation vs. Actual Implementation

---

## Executive Summary

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: Foundation | ✅ Complete | 100% |
| Phase 2: Enrichment Pipeline | ✅ Complete | 100% |
| Phase 3: Gradient Agent + RAG | ✅ Complete | ~95% |
| Phase 4: Deployment | ⚠️ Partial | ~70% |
| Phase 5: Demo UI + Polish | ⚠️ Partial | ~60% |
| **Overall** | **Mostly Complete** | **~85%** |

**162 tests passing** - Core functionality is solid.

---

## Detailed Gap Analysis by Area

### 1. Backend API - Gaps Found

| Feature | Documented | Implemented | Status | Notes |
|---------|------------|-------------|--------|-------|
| IOC CRUD (POST/GET/DELETE) | ✅ | ✅ | Complete | All endpoints working |
| IOC List with filtering | ✅ | ✅ | Complete | Type filter, pagination |
| IOC Enrichment trigger | ✅ | ✅ | Complete | `POST /{ioc_id}/enrich` |
| AI Analysis endpoint | ✅ | ✅ | Complete | `POST /analyze` with agent |
| Health check (basic) | ✅ | ✅ | Complete | Returns `{status: "ok"}` |
| **Health check (enhanced)** | ✅ | ⚠️ | Partial | Documented: DB/Redis/Gradient checks. Actual: Basic only |
| Rate limiting | ✅ | ❌ | **Missing** | `slowapi` integration not found |
| CORS middleware | ✅ | ⚠️ | Partial | Basic CORS, not fully configured |
| Request ID middleware | ✅ | ❌ | **Missing** | For log correlation |
| Structured JSON logging | ✅ | ⚠️ | Partial | `loguru` used but not fully configured for JSON |
| **IOC Bulk Import** | ✅ | ❌ | **Missing** | `POST /api/v1/iocs/bulk` not found |
| **Webhook notifications** | ❌ | ❌ | **Missing** | Listed as future feature but could be prioritized |

---

### 2. Frontend UI (corvid-ui) - Gaps Found

| Component | Documented | Implemented | Status | Priority |
|-----------|------------|-------------|--------|----------|
| InvestigationBoard | ✅ | ✅ | Complete | Main layout shell |
| GraphCanvas | ✅ | ✅ | Complete | Cytoscape wrapper |
| IOCInputBar | ✅ | ✅ | Complete | With auto-type detection |
| DetailPanel | ✅ | ✅ | Complete | Side panel with data |
| SeverityGauge | ✅ | ✅ | Complete | Color-coded 0-10 arc |
| CVECard | ✅ | ✅ | Complete | CVE display component |
| MitreOverlay | ✅ | ✅ | Complete | MITRE technique display |
| EnrichmentCard | ✅ | ✅ | Complete | Per-source enrichment |
| LoadingOverlay | ✅ | ✅ | Complete | Spinner during analysis |
| SeverityLegend | ✅ | ✅ | Complete | Color scale reference |
| **FilterToolbar** | ✅ | ❌ | **Missing** | Type/severity/source filters |
| **LayoutSwitcher** | ✅ | ❌ | **Missing** | Layout algorithm selector |
| **HistoryDrawer** | ✅ | ❌ | **Missing** | Past investigations sidebar |

#### Missing UI Features:
- **Filter system**: No UI for filtering graph by severity, type, or data source
- **Layout switching**: Cannot switch between dagre/cose/concentric/breadthfirst/grid layouts
- **Investigation history**: No sidebar to view/restore past investigations
- **Keyboard shortcuts**: Documented (Escape, Delete, F, R, 1-5, Ctrl+Enter, Ctrl+K, /) but not implemented
- **Right-click context menu**: Not implemented
- **Responsive mobile layout**: Detail panel doesn't collapse to bottom sheet

#### Missing UI Hooks/Stores:
| Item | Status | Notes |
|------|--------|-------|
| useAnalysis | ✅ | Complete |
| useIOC | ✅ | Complete |
| useEnrichment | ✅ | Complete |
| **useGraphLayout** | ❌ | Missing - layout run/animate logic |
| graphStore | ✅ | Complete |
| filterStore | ✅ | Complete |
| **historyStore** | ❌ | Missing - investigation session history |

---

### 3. Worker/Enrichment - Status

| Component | Status | Notes |
|-----------|--------|-------|
| normalizer.py | ✅ Complete | IOC validation, type detection, defanging |
| orchestrator.py | ✅ Complete | Concurrent provider execution |
| enrichment.py | ✅ Complete | Base provider interface |
| tasks.py | ✅ Complete | arq task definitions |
| **abuseipdb.py** | ✅ Complete | AbuseIPDB provider |
| **urlhaus.py** | ✅ Complete | URLhaus provider |
| **nvd.py** | ✅ Complete | NVD CVE search provider |

All enrichment providers are fully implemented.

---

### 4. Agent + Tools - Status

| Component | Status | Notes |
|-----------|--------|-------|
| agent.py | ✅ Complete | Gradient agent integration |
| guardrails.py | ✅ Complete | Input/output validation |
| tools/lookup_ioc.py | ✅ Complete | DB lookup tool |
| tools/search_cves.py | ✅ Complete | CVE search tool |
| tools/enrich_external.py | ✅ Complete | External enrichment trigger |
| tools/search_kb.py | ⚠️ Partial | May be stubbed without KB ID |

---

### 5. Ingestion Pipeline - Status

| Component | Status | Notes |
|-----------|--------|-------|
| nvd.py | ✅ Complete | CVE ingestion from NVD API |
| mitre.py | ✅ Complete | MITRE ATT&CK ingestion |
| advisories.py | ✅ Complete | CISA KEV ingestion |
| loader.py | ✅ Complete | Upload coordinator |
| **Scheduled ingestion** | ❌ Missing | No cron/scheduler for automatic updates |
| **Incremental updates** | ⚠️ Partial | May not track last fetch time |

---

### 6. Database Layer - Status

| Feature | Status | Notes |
|---------|--------|-------|
| IOC model | ✅ Complete | All fields, relationships |
| Enrichment model | ✅ Complete | All fields |
| Analysis model | ✅ Complete | All fields |
| CVEReference model | ✅ Complete | All fields |
| Alembic migrations | ✅ Complete | Migration files exist |

---

### 7. Testing - Status

| Test Category | Documented | Implemented | Status |
|---------------|------------|-------------|--------|
| Unit Tests (backend) | ~160 tests | 162 passing | ✅ Complete |
| UI Component Tests | ~44 tests | Partial | ⚠️ Some exist |
| Store Tests | ~16 tests | Partial | ⚠️ Some exist |
| Lib Tests | ~21 tests | Partial | ⚠️ Some exist |
| Integration Tests | ~10 tests | ✅ | Complete |
| E2E Tests (Playwright) | 3 tests | ❌ | **Missing** |
| Smoke Tests | 6 tests | ✅ | Complete |
| **Frontend E2E** | 3 tests | ❌ | **Missing** |

---

### 8. Deployment & DevOps - Status

| Feature | Documented | Implemented | Status |
|---------|------------|-------------|--------|
| Docker Compose | ✅ | ✅ | Complete |
| Dockerfile (API) | ✅ | ✅ | Complete |
| Dockerfile (UI) | ✅ | ✅ | Complete |
| do-app-spec.yaml | ✅ | ⚠️ | Partial - needs UI static site |
| nginx.conf | ✅ | ✅ | Complete |
| **CI/CD pipeline** | ❌ | ❌ | Missing |
| **Automated deployment** | ❌ | ❌ | Missing |

---

## Priority Matrix: Outstanding Items

### 🔴 High Priority (Core Features)

| Item | Impact | Effort | Why |
|------|--------|--------|-----|
| FilterToolbar UI | High | Medium | Analysts need to filter large graphs |
| LayoutSwitcher UI | High | Low | Critical for graph exploration |
| Health check (enhanced) | Medium | Low | Ops visibility |
| Rate limiting | High | Low | Production hardening |
| CORS full config | Medium | Low | Production hardening |
| HistoryDrawer | Medium | Medium | User experience |

### 🟡 Medium Priority (User Experience)

| Item | Impact | Effort | Why |
|------|--------|--------|-----|
| Keyboard shortcuts | Medium | Low | Power user feature |
| Right-click context menu | Medium | Medium | Graph interaction |
| useGraphLayout hook | Medium | Low | Layout management |
| historyStore | Medium | Low | Session persistence |
| Scheduled ingestion | Medium | Medium | Knowledge base freshness |
| Responsive mobile layout | Low | Medium | Mobile access |

### 🟢 Low Priority (Nice to Have)

| Item | Impact | Effort | Why |
|------|--------|--------|-----|
| IOC Bulk Import | Low | Medium | Future feature |
| Webhook notifications | Low | High | Integration feature |
| Request ID middleware | Low | Low | Debugging aid |
| Structured JSON logging | Low | Low | Log aggregation |
| E2E Playwright tests | Low | High | Test coverage |
| CI/CD pipeline | Low | High | Automation |

---

## Recommendations

### Immediate Actions (This Week)
1. **Add FilterToolbar component** - Essential for usability with real data
2. **Add LayoutSwitcher component** - Simple dropdown, high impact
3. **Implement enhanced health checks** - Add DB/Redis/Gradient connectivity tests
4. **Add rate limiting** to `/analyze` endpoint - Protect against abuse

### Short Term (Next 2 Weeks)
1. **HistoryDrawer + historyStore** - Enable investigation persistence
2. **Keyboard shortcuts** - ESC to deselect, F to fit graph, etc.
3. **Complete CORS configuration** - Production readiness
4. **Add useGraphLayout hook** - Clean up layout management

### Future Considerations
1. **CI/CD pipeline** - GitHub Actions for automated testing/deployment
2. **Bulk IOC import** - For SOC workflows
3. **Webhook notifications** - SOAR integration
4. **STIX/TAXII integration** - Industry standard interop

---

## Test Coverage Summary

| Layer | Files | Tests | Coverage |
|-------|-------|-------|----------|
| Backend Unit/Integration | ~25 | ~130 | ✅ Good |
| Frontend Unit | ~8 | ~15 | ⚠️ Partial |
| Frontend Integration | - | ~5 | ⚠️ Partial |
| E2E | 0 | 0 | ❌ Missing |

---

## Conclusion

Corvid is **functionally complete** for its core purpose:
- ✅ Submit IOCs
- ✅ Enrich with external sources
- ✅ AI-powered analysis with Gradient
- ✅ Visualize in graph UI
- ✅ Store and retrieve analyses

The main gaps are **UI polish** (filters, layout switching, history) and **production hardening** (rate limiting, enhanced health checks). The foundation is solid with 162 passing tests.

**Estimated effort to close high-priority gaps: 2-3 days**

---

*Generated by Gryphon (Grf) - Cyber-punk gryphon robot assistant*
