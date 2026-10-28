# Evaluation

## Methods compared (same detector output, only the grouping differs)

| ID | Method |
|---|---|
| A | Independent alerts – every signal event is its own triage item |
| B | Rule-based – union events sharing any (non-infrastructure) IP within the link window |
| Proposed | Evidence-aware correlation (`docs/CORRELATION.md`) |
| C | TF-IDF over event text (type, signature, tags, port, stage) + DBSCAN (cosine, eps 0.3) |

An embedding-based method was **not** run: no local embedding model is bundled, and adding one would
need its own dependency and a separately tuned, fair comparison.

## Metrics and units

- **Triage items** = incidents + signal events left outside any incident. Reduction is reported against
  method A. The Overview's "event→incident reduction" uses `(raw − incidents) / raw × 100` over *all*
  events, which is large by construction because raw events include context traffic; both are shown
  with their definitions.
- **Grouping P/R/F1** – pair counting over unordered event pairs (same predicted incident vs same
  labelled group), computed exactly from contingency counts.
- **Attack-chain P/R/F1** – stage presence per labelled group; the group is matched to the incident with
  the largest event overlap. Stage order is checked separately.
- **ATT&CK** – technique level (sub-techniques normalised to the parent, e.g. T1071.001 → T1071) and tactic
  level, scored separately; a tactic match never counts as a technique match.
- **Benign escalation** – benign groups whose incident reaches High/Critical.
- **LLM** – per configured model: valid structured-output rate, attempts, latency, validator findings
  (unknown IDs/IPs/techniques, stage upgrades, over-claiming, injection compliance). Usefulness and
  readability need human review and are not automated.

Precision/recall/F1 are computed only when the dataset has labels; otherwise only descriptive statistics.

## Results measured in this build (synthetic demo v1.3.0, default settings)

Measured on the development container (2 vCPU) on 27 Oct 2026. Re-run them on your machine from the
Evaluation lab; numbers will differ slightly in timing.

| Method | Incidents | Triage items | Reduction vs A | Pairwise P | R | F1 | Unrelated alerts merged |
|---|---|---|---|---|---|---|---|
| A independent | 0 | 4,512 | 0 % | – | 0.000 | – | 0 |
| B shared IP | 6 | 10 | 99.78 % | 0.999 | 1.000 | 1.000 | **3** |
| **Proposed** | 6 | 13 | 99.71 % | **1.000** | 1.000 | 1.000 | **0** |
| C TF-IDF + DBSCAN | 23 | 95 | 97.89 % | 0.985 | 0.902 | 0.942 | 0 |

Proposed method on labelled scenarios: attack-chain stages P/R/F1 1.00/1.00/1.00, stage order correct
2/2, ATT&CK techniques 1.00/1.00/1.00 (14 TP), tactics 1.00/1.00/1.00, benign groups escalated 0/3.
Pipeline throughput ≈ 3,900 events/s (detectors ≈ 80 ms, correlation ≈ 2.0 s, incident build ≈ 60 ms
for 8,227 events).

LLM: no Ollama runtime or model was available in the build environment, so **no real model was
evaluated**. The deterministic fallback passed the validator for 6/6 incidents. The integration was
exercised against `scripts/mock_ollama.py` (a test double), which confirmed request/response handling,
validation, retries and rejection of injection-following output – these are not model-quality results.

### How to read these numbers

- The dataset and its labels were written by the same developer as the engine, and scenario parameters
  sit comfortably above the detector thresholds. **Near-perfect scores are expected by construction** and
  show only that the pipeline behaves as designed. They are not evidence of real-world detection
  performance and must not be compared with the base paper's reported results (different data, sensors
  and task).
- The meaningful comparison is relative: B merges the three deliberately placed "shared busy server"
  alerts into unrelated incidents; the proposed method keeps them separate (at the cost of 3 more triage
  items). C groups by behaviour type, not by attack, and leaves many alerts ungrouped.
- Two labels were corrected during development (v1.3.0): the authorised scan also sweeps hosts
  (reconnaissance/T1595 expected) and scenario A contains a Suricata web-attack alert (T1190 expected).
  This is recorded in `data/demo/SCENARIOS.md`.

Suggested next steps for a meaningful evaluation: ZeekData24 / S-DAPT-2026 or a lab capture with an
independently written attack plan, threshold sensitivity sweeps, and a blinded human review of LLM output.
