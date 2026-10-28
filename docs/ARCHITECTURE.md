# Architecture and data flow

## Pipeline

```
Suricata EVE JSON ─┐                                      ┌─> Incident (meta-alert) ──> ATT&CK enrichment
Zeek JSON / TSV  ──┼─> parsers ─> normalise ─> dedupe ─> detectors ─> correlation ─> attack-chain ─> risk + confidence
                   │   (per sensor)  (schema 1.0)  (SHA-256)  (tags)     (links,      reconstruction        │
                   │                                                      groups)                         v
                   └── raw record preserved ────────────────────────────────────────────> evidence panel / reports
                                                                                                          │
                       sanitised structured incident ──> local LLM (Ollama) ──> validator ──> summary ────┘
                                                         (or deterministic template)
```

| Layer | Module | Deterministic? |
|---|---|---|
| Ingestion & parsing | `app/ingestion/{suricata,zeek,service}.py` | yes |
| Normalisation & schema | `app/normalization/schema.py` | yes |
| Behaviour detectors | `app/correlation/detectors.py` | yes |
| Correlation & grouping | `app/correlation/engine.py` | yes |
| Attack-chain reconstruction | `app/attack_chain/reconstruct.py` | yes |
| ATT&CK enrichment | `app/attack_mapping/{catalog,mapper}.py` + `data/mappings/*.json` | yes |
| Risk & confidence | `app/risk/scoring.py` | yes |
| Incident formation / persistence | `app/services/{incident_builder,pipeline}.py` | yes |
| LLM assistance | `app/llm/{sanitize,prompt,client,validate,fallback,service}.py` | **LLM text only** |
| Optional ML experiment | `app/evaluation/runner.py` (TF-IDF + DBSCAN) | yes (seed-free algorithm) |
| API | `app/api/routes.py`, `app/main.py` | – |
| UI | `frontend/src` | – |

**Boundary:** correlation, stages, mappings, risk and confidence are computed without any model. The
LLM receives a finished, sanitised incident and can only produce a separate `AISummary` row after
validation. It cannot change scores, statuses or any other record, and its output never triggers actions.

## Data model (SQLAlchemy, `app/models`)

```
Dataset 1─* IngestionJob 1─* RejectedRecord
Dataset 1─* Event (normalised record + raw_payload + detector_tags)
Dataset 1─* CorrelationRun 1─* EventLink (pairwise evidence: score, components, shared entities, rule)
Dataset 1─* Incident *─* Event   (via IncidentEvent, with the event's stage)
Incident 1─* AttackStage | AttackMapping | AISummary | AnalystNote | StatusChange
Dataset 1─* EvaluationRun (params + results JSON)
Setting (validated AnalysisSettings JSON), Analyst
```

- Event IDs are `EV-` + 16 hex chars of SHA-256(sensor|log|canonical raw record): stable and reproducible.
- Incident IDs are `INC-` + the first 8 hex chars of SHA-256(sorted member event IDs). Re-running
  correlation keeps an analyst's status, notes and summaries when the membership is unchanged.
- Ground-truth labels (`Dataset.labels`) are read only by the evaluation module.

## Schema initialisation and migration

`init_db()` calls `Base.metadata.create_all()` at startup – fine for a single-user prototype. To move to
PostgreSQL: set `NTDCP_DATABASE_URL=postgresql+psycopg://…`, add Alembic (`alembic init`, autogenerate
from `app.models`), and replace the SQLite-only SQL functions in `app/services/queries.py`
(`strftime`, `json_array_length`) with `date_trunc` / `jsonb_array_length`.

## Concurrency

Handlers are synchronous and run in FastAPI's threadpool, so long work (correlation ~2–3 s on the demo,
LLM calls up to the configured timeout) never blocks the event loop. Evaluation runs are background
jobs (`BackgroundTasks`), polled by the UI. Database sessions commit before the response is sent.

## Security controls

| Risk | Control |
|---|---|
| Large uploads / DoS | streamed size check (`NTDCP_MAX_UPLOAD_MB`), per-field length caps, candidate-pair cap per entity |
| Path traversal | uploads are parsed in memory and never written to disk; the SPA file handler checks resolved paths |
| Malformed input | every rejected record stored with line number + reason; binary files refused (415) |
| XSS | React escapes all text; JSON shown via text nodes; HTML reports escape every value and are served with a restrictive CSP |
| CSV injection | exported cells starting with `= + - @` are prefixed |
| SQL injection | SQLAlchemy ORM / bound parameters only |
| Prompt injection | allow-listed fields, control-char stripping, instruction-pattern redaction, separate system/data channels, schema-constrained JSON output, validator, bounded retries, fallback |
| Model actions | no tool use, no shell, no DB writes from model output; recommendations restricted to investigative steps (validator rejects commands) |
| Data leaving the host | only the configured local Ollama URL is contacted; no cloud API |
| Secrets | none required; `.env` is git-ignored; nothing secret is logged or shown |
| CORS / headers | explicit origin list; `nosniff`, `X-Frame-Options: DENY`, `no-referrer` |
