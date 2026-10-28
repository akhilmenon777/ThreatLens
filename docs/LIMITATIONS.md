# Limitations and future work

## Limitations

1. **Network telemetry only.** No host, endpoint, authentication-server or process data. Access,
   post-compromise activity and data theft can only be inferred, never confirmed.
2. **Encrypted traffic.** TLS hides payloads; beaconing and exfiltration rely on timing, volume and
   metadata (SNI, JA3 where Suricata provides it).
3. **Heuristic thresholds and weights.** Detector thresholds, link weights and risk weights are expert
   defaults, configurable but not learned or tuned on real data. Scores are not calibrated probabilities.
4. **Evaluation data.** The demo dataset is synthetic and labelled by the engine's author; results are
   near-perfect by construction (see `docs/EVALUATION.md`). No public dataset (e.g. ZeekData24) has been
   evaluated yet.
5. **LLM quality unmeasured on real models.** The Ollama integration, validator and fallback are tested,
   but no real Qwen/DeepSeek output could be evaluated in the build environment. The validator catches
   structural and factual-reference errors, not subtle misinterpretation.
6. **Prompt-injection defence is pattern-based.** Instruction-like text is detected with regular
   expressions; novel phrasings could pass the sanitiser (the output validator and the fact that the
   LLM cannot act provide further layers).
7. **Partial ATT&CK coverage.** 21 techniques across 11 tactics relevant to network evidence; mappings
   come from hand-written rules.
8. **Single-user prototype.** No authentication or role-based access; the analyst name is chosen in the
   UI. SQLite and in-process background tasks; not built for multi-tenant or high-volume production.
9. **Batch correlation.** Correlation re-runs over the whole dataset; there is no streaming ingestion.
   The demo (8k events) takes ~3 s; very large captures need incremental correlation.
10. **SQLite-specific SQL** in a few read queries (see `docs/ARCHITECTURE.md`).

## Future work

- Evaluate on ZeekData24, S-DAPT-2026 and an independently scripted lab attack; threshold sensitivity sweeps.
- Run and compare real local models (latency, validity, blinded human review of usefulness).
- Streaming/incremental correlation and Suricata/Zeek live tailing.
- Optional embedding-based semantic similarity as an extra link signal, compared fairly against TF-IDF.
- Authentication, roles and audit logging; Alembic migrations and PostgreSQL.
- Load the full MITRE ATT&CK STIX bundle with version pinning.
