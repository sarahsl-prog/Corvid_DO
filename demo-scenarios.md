# Corvid Demo Scenarios

Brainstorming document for hackathon demo presentation and live demonstrations.
The goal is to show Corvid's full value chain: **IOC in → enrichment → AI analysis → actionable intel out**.

---

## What Corvid Does (Elevator Pitch)

> A SOC analyst drops an IP address, domain, file hash, or URL into Corvid and gets back a
> structured threat intel report in seconds — severity score, confidence, mapped MITRE ATT&CK
> techniques, related CVEs, and recommended actions. No pivoting between 6 dashboards.

---

## Scenario 1 — "The Suspicious IP" (Most Impactful, Start Here)

**Storyline:** A firewall alert fires at 2 AM flagging outbound traffic to `203.0.113.42`.
The on-call analyst needs to decide: block it or ignore it?

**Demo Flow:**

1. POST `/api/v1/analyses/analyze` with:
   ```json
   {
     "iocs": [{"type": "ip", "value": "203.0.113.42"}],
     "context": "Seen in outbound traffic from prod web server at 02:15 UTC",
     "priority": "high"
   }
   ```
2. Show the agent calling tools in real time:
   - `lookup_ioc` → checks local DB
   - `enrich_ioc_external` → AbuseIPDB reports 85% abuse confidence, URLhaus shows no matches
   - `search_knowledge_base` → retrieves related CVE advisories
3. Response returns:
   - Severity **7.8**, Confidence **0.82**
   - MITRE T1071 (Application Layer Protocol C2)
   - Recommended actions: "Block at perimeter, hunt for lateral movement, preserve logs"
4. Open the React graph view — show the IOC node with color-coded severity, click to expand

**Why it lands:** Simulates a real midnight SOC scenario. Decision goes from "ambiguous alert"
to "block it, here's why" in 12 seconds.

---

## Scenario 2 — "The Phishing Campaign Hash"

**Storyline:** IR team receives a hash from a threat sharing feed during a live phishing campaign.

**Demo Flow:**

1. Submit SHA-256 hash: `44d88612fea8a8f36de82e1278abb02f` (example)
2. Context: "Received from ISACand threat sharing feed – suspected Emotet loader"
3. Show enrichment → NVD finds no CVEs (expected for a hash)
4. Agent returns:
   - MITRE T1204 (User Execution) + T1566 (Phishing)
   - Recommended actions referencing Emotet playbook steps
   - Related IOCs (if KB has prior campaign data): C2 domains
5. Analyst tags it with `["emotet", "phishing-campaign-2026-03"]` via a second API call

**Why it lands:** Shows that Corvid handles non-IP IOC types and can chain into campaigns.

---

## Scenario 3 — "Batch Triage — The Log Dump"

**Storyline:** After a breach, the DFIR team dumps 5 suspicious indicators from memory.
They need fast triage to prioritize.

**Demo Flow:**

1. Submit all 5 IOCs in a single request:
   ```json
   {
     "iocs": [
       {"type": "ip",      "value": "45.33.32.156"},
       {"type": "domain",  "value": "update-service.net"},
       {"type": "url",     "value": "http://malicious.example.com/payload.exe"},
       {"type": "hash_sha256", "value": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
       {"type": "ip",      "value": "8.8.8.8"}
     ],
     "context": "Extracted from compromised endpoint memory dump",
     "priority": "high"
   }
   ```
2. Show the `partial` or `completed` status with per-IOC severity scores
3. Visualize in the graph: nodes with severity heat-map — red=block now, green=false positive
4. Point out 8.8.8.8 gets low severity → agent correctly identifies it as Google DNS

**Why it lands:** Shows the **batch analysis** capability. The graph view makes risk ranking
immediately visual. The Google DNS result shows the AI applies context, not just blacklists.

---

## Scenario 4 — "The CVE Connection" (Good for Technical Audience)

**Storyline:** A Log4Shell indicator appears in IDS logs. The analyst wants the full CVE context
without opening NIST NVD separately.

**Demo Flow:**

1. Submit domain `log4shell-scanner.evilexample.com` with context
   "Found in HTTP User-Agent header — appears to be Log4j exploit probe"
2. Show agent calling `search_knowledge_base` → retrieves CVE-2021-44228 document from KB
3. Response includes:
   - Related CVEs: `["CVE-2021-44228", "CVE-2021-45046"]`
   - MITRE T1190 (Exploit Public-Facing Application)
   - CVSS 10.0 critical
   - Recommended: "Patch Log4j immediately, check for JNDI strings in all logs"
4. Bonus: show the KEV flag — "This CVE is in the CISA Known Exploited Vulnerabilities catalog.
   CISA due date: 2021-12-24"

**Why it lands:** Demonstrates the RAG knowledge base in action. Real CVE data + real KEV
urgency, cited automatically.

---

## Scenario 5 — "The Investigation Board" (Frontend Focus)

**Storyline:** Showcase the React UI and graph-based investigation workflow.

**Demo Flow:**

1. Open Corvid UI, enter one IP in the IOCInputBar
2. Watch the node appear in Cytoscape.js graph canvas, colored by severity
3. Click node → DetailPanel opens showing enrichment data + AI summary
4. Click "Analyze Related IOCs" — submits related IOCs from the first analysis
5. New nodes appear, connected by edges showing relationships
6. Use FilterToolbar to filter to "Critical only" — non-critical nodes fade
7. Use HistoryDrawer to pull up a previous analysis from earlier in the demo
8. Switch layout (hierarchical vs. force-directed) with LayoutSwitcher

**Why it lands:** Visually spectacular for a live demo. Shows the "investigation board" metaphor —
like a detective's evidence wall, but automated.

---

## Scenario 6 — "Knowledge Base Build" (Technical Deep Dive)

**Storyline:** Show how Corvid ingests threat intel data before the demo (behind the scenes).

**Walk-through (not live — use screenshots or pre-recorded):**

1. Show `python -m corvid.ingestion.loader --dry-run --years=2`
2. NVD: 20,000+ CVEs fetched from last 2 years
3. MITRE ATT&CK: 200+ Enterprise techniques + sub-techniques
4. CISA KEV: ~1,000 known exploited CVEs
5. Upload to Gradient KB: `~21,000 documents`
6. Show a KB document: rich content combining CVE ID, description, CVSS, affected products,
   KEV status, and MITRE mappings

**Why it lands:** Shows Corvid has real data behind the AI, not hallucinations. The KB is the
"security library" the AI reasons over.

---

## Scenario 7 — "Alert Fatigue Killer" (Business/Executive Pitch)

**Storyline:** Frame Corvid as the solution to analyst burnout.

**Narrative points:**

- Average SOC team receives 11,000+ security alerts per day (cite: IBM Security report)
- Analysts spend 60–70% of time on triage, not actual investigation
- Corvid auto-triages in seconds: severity score + confidence + recommended action
- Low confidence analyses are flagged for human review; high confidence block-recommendations
  can be auto-actioned via SOAR integration (future roadmap)
- Show the API — this is integration-ready: SIEM → Corvid → SOAR is a 2-hour integration

**Demo props:** Show a fake SIEM alert, copy the IOC, paste into Corvid UI, show report.
Time it: "12 seconds vs. 20 minutes of manual research."

---

## Technical Demo Tips

### Preparing Canned Data

- Pre-load the DB with 10–15 IOCs spanning all types (IP, domain, hash, URL)
- Run enrichment ahead of time so the demo doesn't wait for slow external APIs
- Have a "fast demo" env var (`CORVID_AGENT_TIMEOUT_SECONDS=10`) to avoid long waits

### If the Gradient API is Unavailable

The agent falls back to `_mock_agent_response()` automatically when no API key is set.
For demo purposes:
- Load a real enrichment result from a previous run
- The mock response builds a realistic-looking output from the enrichment data
- Swap in a pre-recorded JSON response if needed

### API Call Order for Live Demo

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. Submit IOC for full analysis
curl -X POST http://localhost:8000/api/v1/analyses/analyze \
  -H "Content-Type: application/json" \
  -d '{"iocs":[{"type":"ip","value":"203.0.113.42"}],"context":"Outbound C2 traffic","priority":"high"}'

# 3. Retrieve by ID (shows persistence)
curl http://localhost:8000/api/v1/analyses/{analysis_id}

# 4. List all IOCs accumulated during demo
curl http://localhost:8000/api/v1/iocs/
```

### Frontend Talking Points

- React 19 + Cytoscape.js for graph rendering
- Zustand for state management
- Vite for fast dev builds
- Full TypeScript with Pydantic-mirrored types

---

## Demo Environment Recommendations

### Option A — Local Docker Compose (Safest)

```bash
docker-compose up -d   # PostgreSQL + Redis
uvicorn corvid.api.main:app --reload
cd corvid-ui && npm run dev
```

All data is local, no network dependency for DB/Redis. Only Gradient API needs internet.

### Option B — DigitalOcean App Platform (Most Impressive)

- Deploy to DO App Platform (already configured per `deploy/`)
- Use managed Postgres + Redis add-ons
- Show the DO logo — relevant for hackathon judges
- Pre-warm the deployment so cold-start doesn't hurt demo timing

### Option C — Local with Mock Agent (Zero External Dependencies)

- Set `CORVID_GRADIENT_API_KEY=` (empty) — agent uses mock response
- Still shows enrichment (URLhaus/NVD are keyless)
- Use for offline/airplane-mode demos

---

## Questions to Clarify Before Demo

1. **Live API keys available?** If yes, use real AbuseIPDB + NVD + Gradient for maximum impact.
   If not, the mock path still demos the concept well.

2. **Pre-load the KB?** Running the full NVD/MITRE ingestion takes 10–20 minutes.
   Recommend doing this the night before and confirming KB document count.

3. **Target audience?** Technical judges → lead with Scenario 4 (CVE connection) + Scenario 6
   (KB build). Business judges → lead with Scenario 1 (suspicious IP) + Scenario 7 (alert fatigue).

4. **Time budget?** For a 5-minute demo: Scenarios 1 + 5 (visual).
   For a 10-minute demo: Scenarios 1 + 3 + 4 + 5.

5. **UI polish status?** If the graph UI isn't fully polished, lead with the API/curl demo and
   treat the UI as a bonus. The API itself tells the story clearly.
