# Implementation report

Build date: 27 Oct 2026. Environment: Linux container, Python 3.13, Node 22, 2 vCPU, no GPU,
no Ollama/Suricata/Zeek installed.

## What works (implemented and verified)

| Area | Status | How it was verified |
|---|---|---|
| Suricata EVE JSON parsing (alert, dns, http, tls, flow, ssh, anomaly, fileinfo) | ✅ | unit tests; demo import |
| Zeek JSON + classic TSV (conn, dns, http, ssl, ssh, notice, files) | ✅ | unit tests (TSV incl. malformed line); demo `zeek_files.tsv.log` |
| Normalisation to schema 1.0, UTC timestamps, raw payload kept, warnings | ✅ | unit + API tests |
| Malformed / duplicate handling with stored reasons | ✅ | API test: 7 rejected + 1 duplicate in demo EVE file; UI "Why rejected?" |
| Detectors, linking, grouping, over-merge safeguards | ✅ | 14 correlation unit tests incl. busy-server and infrastructure-IP cases |
| Attack chain with OBSERVED / INFERRED / NOT OBSERVED | ✅ | unit + API tests |
| ATT&CK mapping validated against versioned local catalog | ✅ | unit tests (invalid technique / wrong tactic rejected) |
| Separate risk and confidence with breakdowns | ✅ | unit tests (repeat alerts not double-counted, scanner penalty) |
| Ollama client, model discovery, AI Off / Cached / Live modes | ✅ (HTTP path) | API tests with mocked client; live HTTP run against `scripts/mock_ollama.py` |
| Output validation, bounded retry, deterministic fallback | ✅ | 13 LLM unit tests; injection-obeying mock output rejected → fallback |
| Prompt-injection resistance (scenario F) | ✅ | sanitiser redacts the User-Agent instruction; prompt contains no instruction text; validator rejects compliance |
| Analyst workflow (status, assignee, FP flag, reopen, notes, history) persisted | ✅ | API test incl. survival across correlation re-run; browser E2E incl. page reload |
| Reports: incident JSON / CSV / HTML, incidents CSV, evaluation JSON / Markdown | ✅ | API tests (HTML escaping, disclaimer, synthetic label) |
| Evaluation lab: 4 methods, labelled metrics, reproducible params, export | ✅ | API test + browser E2E; results in `docs/EVALUATION.md` |
| 9-page UI (overview, incidents, investigation, events, ATT&CK, evaluation, ingestion, reports, settings) | ✅ | 8 Vitest tests; 11-step Playwright E2E; screenshots reviewed at 1440 px |
| Settings validation and system status | ✅ | API test (bad thresholds / timezone → 422) |

## Test results (actual runs)

- `backend: python -m pytest` → **46 passed** (ingestion 6, correlation 14, LLM 13, metrics 3, API/integration 10).
- `frontend: npm test` → **8 passed**; `tsc -b` clean; `vite build` succeeds (route-level code splitting).
- `scripts/e2e_smoke.py` (Playwright/Chromium against the built app) → **11/11 steps passed**: load demo via UI,
  overview, open incident, timeline + raw-payload drawer, template summary, status + note persisted after reload,
  HTML report export, unassigned events, ATT&CK drill-down, evaluation run, Ollama connection check.

## Not verified / incomplete

- **Real local models.** No Ollama runtime or Qwen/DeepSeek model was available, so model output quality,
  real latency and real schema-validity rates are unmeasured. Run the Evaluation lab with "Include local LLM
  evaluation" on your machine.
- **Real Suricata/Zeek captures.** Parsers follow the documented formats and were tested on synthetic records only.
- **Public datasets** (ZeekData24, S-DAPT-2026) were not evaluated.
- No authentication / multi-user access control (single-user local prototype, by scope).

## Design decisions worth noting

- The LLM summarises *after* deterministic correlation instead of feeding clustering (as in the base paper),
  so a hallucinated summary cannot change incident membership, scores or mappings.
- No GNN/transformer component: no labelled network training data exists in scope and every decision must be
  explainable. TF-IDF + DBSCAN is included only as an evaluation experiment.
- Incident IDs are derived from membership so analyst work survives re-correlation.
- During development the popular-entity rule was changed from "many counterparts" to "many distinct sources
  reaching it" (fan-in): the first version wrongly blocked the attacker and the authorised scanner and split
  their activity into dozens of incidents. Demo labels were corrected in v1.3.0 (see `data/demo/SCENARIOS.md`).
