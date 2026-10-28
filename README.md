# ThreatLens — Network Threat Detection and Attack Correlation Platform

A passive blue-team analysis layer that sits above **Suricata** and **Zeek**. It turns thousands of
disconnected network alerts into a small number of **evidence-backed, explainable incidents**, then
helps an analyst investigate them:

- normalises Suricata EVE JSON and Zeek JSON/TSV into one versioned schema (the raw record is kept);
- correlates events with temporal, entity and behavioural evidence, with safeguards against over-merging;
- reconstructs the probable attack chain, labelling every stage **OBSERVED**, **INFERRED** or **NOT OBSERVED**;
- maps behaviour to MITRE ATT&CK (local, versioned subset) with method, confidence and evidence;
- scores **risk** (0–100) and **correlation confidence** (0–1) separately, with full breakdowns;
- writes analyst summaries with a **local** LLM through Ollama (Qwen / DeepSeek), validated against the
  evidence, with a deterministic fallback when the model is unavailable or its output fails validation;
- persists analyst workflow (status, assignee, false-positive flag, notes, history) and exports reports;
- includes an evaluation lab that compares the method against baselines on labelled scenarios.

**New in this version**

- **Hybrid dataset: UWF-ZeekData24 + AIT-ADS in one view.** The network layer (153 k labelled Zeek connections,
  UWF) and a host / IDS layer (171 k Wazuh, Suricata and AMiner alerts from 8 attack scenarios of the AIT Alert
  Data Set) import together as **one** dataset. New parsers for Wazuh host alerts, Suricata alerts forwarded by
  Wazuh (EVE and fast.log) and AMiner anomalies; host-log detectors (web-scan bursts, repeated auth failures,
  root sudo, audit anomalies, high-entropy DNS); a *Privilege escalation* stage; per-source breakdown on
  *Dataset insights*. See section 4c.
- **Windows one-click start:** double-click `run.bat`.

- **UWF-ZeekData24 dataset bundled** (`data/uwf/`, 153 k real Zeek conn records from the University of West
  Florida cyber range, labelled with MITRE ATT&CK tactics/techniques). One click imports it; the labels are kept
  apart as ground truth and drive the *Dataset insights* page and the evaluation lab.
- **Redesigned UI** – same warm-white / gold palette, new espresso sidebar, hero dashboards, donut/area charts,
  a *Dataset insights* page, ground-truth labels on events and incidents, multi-file upload with progress.
- Connection-only detectors (brute force against auth services, high-rate service probing, internal remote-admin
  fan-out) so conn-log datasets without IDS alerts are still analysed; a *Lateral movement* stage; faster
  correlation (linear-time scan windows, cached dashboards) for 150 k+ events.

> **Incidents are hypotheses, not proof of attack.** The demo data is synthetic. This is a local
> research/education prototype, not a production-hardened SOC product.

---

## 1. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11+ (tested 3.13) | backend, tests |
| Node.js | 20+ (tested 22) | frontend |
| Ollama | any recent | *optional* – local AI summaries |
| Suricata / Zeek | any | *optional* – your own telemetry (demo data needs neither) |

## 2. Install

```bash
# from the project root
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

cd frontend && npm install && cd ..
cp .env.example .env                 # optional; defaults work as-is
```

## 3. Run

**Option A – development (hot reload, two processes):**

```bash
# terminal 1
cd backend && python -m uvicorn app.main:app --reload --port 8000
# terminal 2
cd frontend && npm run dev
```
Open http://localhost:5173 (the dev server proxies `/api` to port 8000). On Linux/macOS `scripts/dev.sh`
starts both; on Windows use `scripts/dev.ps1`.

**Option B – single process:**

```bash
cd frontend && npm run build && cd ..
cd backend && python -m uvicorn app.main:app --port 8000
```
Open http://127.0.0.1:8000 (the backend serves `frontend/dist`). `scripts/serve.sh` does both steps.

API documentation (OpenAPI/Swagger): http://127.0.0.1:8000/docs

### Database
SQLite is created automatically on first start (`runtime/ntdcp.db`, tables created by
`init_db()`). Delete the `runtime/` folder to start from scratch. Set `NTDCP_DATABASE_URL` for another
SQLAlchemy database (see `docs/ARCHITECTURE.md` for the PostgreSQL migration notes).

## 4. Load the demo data

Click **Load demo data** on the Overview or *Data ingestion* page, or:

```bash
curl -X POST http://127.0.0.1:8000/api/demo/load
```
This ingests ~8,200 synthetic Suricata + Zeek records (scenarios A–G, see `data/demo/SCENARIOS.md`)
and runs correlation. The data is deterministic; regenerate it with
`python scripts/generate_demo_data.py`.

## 4b. Load the UWF-ZeekData24 dataset

On **Overview** (empty state) or **Data ingestion → UWF-ZeekData24 (bundled)** pick the 2025 capture, the 2024
capture or both and press **Import**. The import runs in the background with a progress bar (≈1 min for the 2025
part, ≈2 min for the full 153 k records) and then correlates automatically. Or:

```bash
curl -X POST http://127.0.0.1:8000/api/uwf/load -H 'content-type: application/json' -d '{"parts":["2025","2024"]}'
curl http://127.0.0.1:8000/api/tasks/<id>          # poll progress
```

| What | How it is handled |
|---|---|
| CSV columns `src_ip_zeek`, `dest_port_zeek`, … | converted back to Zeek conn records and parsed by the normal Zeek parser |
| `label_tactic`, `label_technique`, `label_binary`, `label_cve` | removed **before** hashing/storage; kept in the `event_labels` table (evaluation + display only) |
| rows marked `Duplicate` (same connection in several tactic files) | one event, several labels |
| UWF lab hosts `143.88.0.0/16` | added to *Internal networks* automatically (Settings) |

Other UWF CSV parts can be uploaded on **Data ingestion** (format *UWF-ZeekData CSV* or auto-detect; several files at once).
The *Dataset insights* page shows the traffic profile, labelled tactics vs. what the platform detected, and
event-level precision/recall; **Evaluation lab** scores every grouping method against the labels.

Measured on the full bundled set (default settings): 153,140 events → 49,861 flagged → 772 incidents;
event-level precision 1.00, recall 0.65 (Reconnaissance 80 %, Credential Access 56 %; tactics that leave no
distinctive trace in conn metadata – e.g. Persistence over SMB – are not detected and are shown as such).

## 4c. The hybrid dataset (UWF-ZeekData24 + AIT-ADS)

**Windows:** double-click `run.bat` (it finds Python, installs the packages into `backend\_deps` on first run,
starts the server and opens the browser). Then on **Overview** click **Import hybrid dataset (UWF + AIT)**, or on
**Data ingestion** choose a preset (*Hybrid (all)*, *UWF only*, *AIT only*). The hybrid import + correlation
takes ≈3–5 min and needs ≈3 GB of free RAM.

```bash
curl -X POST http://127.0.0.1:8000/api/uwf/load -H 'content-type: application/json' -d '{"parts":["2025","2024","ait"]}'
```

| Layer | Source | Events | Sensors in the app |
|---|---|---|---|
| Network connections | UWF-ZeekData24 (University of West Florida cyber range, 2024 + 2025) | 153,140 | `zeek` |
| Host / IDS alerts | AIT Alert Data Set (AIT LDS V2 testbed, Jan–Feb 2022, 8 scenarios) – Landauer, Skopik, Wurzenberger, Zenodo 10.5281/zenodo.8263181, CC BY 4.0 | 170,265 | `wazuh`, `suricata`, `aminer` |

How the AIT part is prepared and labelled (`scripts/build_ait_subset.py`, output in `data/ait/`):

- **Balanced subset.** The full AIT-ADS has 2.66 M alerts, ~1.6 M of them one repeated Wazuh rule (*Web server
  400 error code*, from dirb). Alerts are grouped by scenario, file, alert type and attack phase; groups of
  ≤ 1,500 are kept completely, bigger ones are thinned evenly over time. 170,850 alerts are kept (records are
  copied unchanged); `data/ait/manifest.json` lists every group's original and kept counts.
- **Labels.** The publisher's `labels.csv` gives attack-phase time windows (network/service scans, dirb, WPScan,
  webshell, cracking, reverse shell, privilege escalation, service stop, DNSteal). Normal alerts keep firing during
  those windows, so an alert is labelled with the phase only when its alert type is clearly elevated inside the
  window (count ≥ 5 × the same type's baseline rate outside all windows + 1), computed on the full data before
  thinning. Phases map to ATT&CK tactics (e.g. dirb → Reconnaissance / T1595.003, privilege escalation →
  Privilege Escalation / T1548.003, DNSteal → Exfiltration / T1048.003). Labels are evaluation-only, as for UWF.
- **Timestamps are not shifted.** The two sources come from different testbeds and years, so the timeline shows
  a 2022 block (AIT) and a 2024–2025 block (UWF). No cross-source links are invented.

Measured on the hybrid set (default settings): 323,405 events → 179,513 flagged → 813 incidents (772 UWF,
41 AIT – including one multi-stage incident per attack scenario); event-level precision 0.99, recall 0.76,
F1 0.86. Per source: Zeek recall 0.65, Wazuh 0.99, AMiner 0.76, Suricata 0.23. Offline password cracking,
reverse shells and DNSteal leave almost no alert trace and are reported as missed.

## 5. Your own Suricata / Zeek data (optional)

Upload files on **Data ingestion** (max 50 MB each, configurable):

- Suricata: `eve.json` (one JSON object per line).
- Zeek: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `ssh.log`, `notice.log`, `files.log` in JSON
  (`LogAscii::use_json=T`) or classic TSV. JSON records need `_path` or a recognisable file name.

Tips: enable `community-id: yes` in Suricata and the Community ID package in Zeek – matching IDs give
the strongest cross-sensor links. Create a new dataset per capture. Capture only in an authorised,
isolated lab; the platform itself never sends packets or takes response actions.

## 6. Local LLM (Ollama) – optional

```bash
# install from https://ollama.com, then:
ollama serve                      # if not already running as a service
ollama pull qwen2.5-coder:7b      # primary (configurable)
ollama pull deepseek-r1:7b        # secondary (configurable)
```
In **Settings → Local LLM assistance**: check the URL (default `http://127.0.0.1:11434`), press
**Test connection & discover models**, put the installed model names in *Primary* / *Secondary*, choose
the AI mode, and save. Any other Ollama model names can be used.

| Mode | Behaviour |
|---|---|
| **Off** | deterministic template summaries only |
| **Cached** (default) | reuse a stored summary while the incident's evidence hash is unchanged; otherwise show a template summary |
| **Live local AI** | request a new summary from Ollama (validated; falls back on failure or timeout) |

On a laptop without a GPU a 7B model can take 30–120 s per summary – raise the timeout in Settings if
needed. To try the integration without a model, run `python scripts/mock_ollama.py` (a test double that
imitates the Ollama API; **not** a language model).

## 7. Tests

```bash
cd backend && python -m pytest            # 48 unit + integration tests (incl. UWF import/labels/analytics)
cd frontend && npm test                   # 8 component/page tests (Vitest)
# browser end-to-end (needs the app on :8000 serving the build):
pip install playwright && python -m playwright install chromium
python scripts/e2e_smoke.py
```

## 8. Evaluation

**Evaluation lab → Run evaluation** (or `POST /api/evaluation/run`). It runs four grouping methods on
the active dataset – A: every alert separately, B: shared IP + time window, the proposed evidence-aware
correlation, and C: TF-IDF + DBSCAN – and scores them against the dataset's labels (demo only). Every
run stores its parameters and can be exported as Markdown/JSON. Tick *Include local LLM evaluation* to
also measure the configured Ollama models. See `docs/EVALUATION.md`.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| UI says "Backend unreachable" | start the backend on port 8000; check `NTDCP_CORS_ORIGINS` if you changed ports |
| "No telemetry loaded yet" | load the demo or upload logs |
| `Demo data not found` | `python scripts/generate_demo_data.py` |
| Ollama "not reachable" | `ollama serve`; check the URL in Settings; firewall |
| "Model … is not installed" | `ollama pull <name>` or change the model name in Settings |
| Summaries always "deterministic fallback" | AI mode is Off/Cached, Ollama is down, the request timed out, or the model output failed validation (the reasons are shown on the incident) |
| A Zeek file is rejected | make sure it is JSON or TSV with a `#fields` header, and that the log type is recognisable |
| Start fresh | stop the backend and delete `runtime/` |
| Windows: `Python was not found` | install Python 3.11+ from python.org with "Add python.exe to PATH", or use `run.bat` (it also tries the `py` launcher) |
| Windows: `Unknown timezone 'UTC'` (older copies) | fixed in this version; for named zones such as `Asia/Kolkata` install `tzdata` (already in requirements) |
| Windows: `No module named uvicorn` after `pip install` | your Python installed packages somewhere unexpected – use `run.bat`, which installs into `backend\_deps` |

## 10. Known limitations

See `docs/LIMITATIONS.md`. In short: network telemetry only, heuristic (uncalibrated) scores, a partial
ATT&CK subset, synthetic evaluation data written by the same developer as the engine, and LLM quality
that has to be measured on your own hardware and models.

## Project layout

```
backend/app/        FastAPI app: ingestion/, normalization/, correlation/, attack_chain/,
                    attack_mapping/, risk/, llm/, evaluation/, reporting/, services/, api/
backend/tests/      pytest suite
frontend/src/       React + TypeScript UI (pages/, components/, layouts/, api/, lib/)
data/demo/          synthetic dataset + labels + SCENARIOS.md
data/uwf/           UWF-ZeekData24 CSV parts (2024/, 2025/) with MITRE ATT&CK labels
data/mappings/      ATT&CK catalog subset + deterministic mapping rules (versioned)
docs/               architecture, correlation method, evaluation, limitations, implementation report
scripts/            demo generator, mock Ollama, e2e smoke test, start scripts
```

Research basis: Ferazza et al. (2026), "From logs to tactics", *Int. J. Inf. Secur.* 25:79 – adapted from
endpoint/syslog telemetry to network telemetry. The paper's reported results are the paper's and are
not claimed for this implementation.
