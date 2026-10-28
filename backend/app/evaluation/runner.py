"""Evaluation laboratory: runs baselines and the proposed method on the active
dataset and scores them against the dataset's ground-truth labels.

Ground truth (labels.json for the synthetic demo) is loaded ONLY here and never
passed to detectors or the correlation engine. Without labels, only descriptive
statistics are reported – no precision/recall/F1 is computed.
"""
from __future__ import annotations

import copy
import time
from collections import Counter, defaultdict

from sqlalchemy.orm import Session

from app.attack_mapping.catalog import get_catalog
from app.core.config import AnalysisSettings
from app.correlation.detectors import run_detectors
from app.correlation.engine import baseline_independent, baseline_rule_based, correlate
from app.correlation.model import EventView
from app.evaluation.metrics import SEVERITY_RANK, order_correct, pairwise_grouping, prf, set_prf
from app.models import Dataset, EvaluationRun
from app.services.incident_builder import build_incident
from app.services.pipeline import load_views

ENGINE_VERSION = "evidence-aware-correlation 1.0"


def _assignment(groups: list[list[str]], min_size: int) -> dict[str, str]:
    out = {}
    for i, g in enumerate(groups):
        if len(g) >= min_size:
            for e in g:
                out[e] = f"g{i}"
    return out


def _describe(name: str, groups: list[list[str]], n_events: int, n_signal: int, min_size: int) -> dict:
    incidents = [g for g in groups if len(g) >= min_size]
    in_inc = sum(len(g) for g in incidents)
    triage_items = len(incidents) + (n_signal - in_inc)
    return {
        "method": name, "input_events": n_events, "signal_events": n_signal, "incidents": len(incidents),
        "signal_events_in_incidents": in_inc, "unassigned_signal_events": n_signal - in_inc,
        "unassigned_events_total": n_events - in_inc, "triage_items": triage_items,
        "reduction_all_events_pct": round((n_events - len(incidents)) / n_events * 100, 2) if n_events else None,
        "triage_reduction_vs_independent_pct": round((n_signal - triage_items) / n_signal * 100, 2) if n_signal else None,
        "largest_incident": max((len(g) for g in incidents), default=0),
    }


def _tfidf_dbscan(views: list[EventView], min_size: int) -> tuple[list[list[str]] | None, str]:
    try:
        from sklearn.cluster import DBSCAN
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError:  # pragma: no cover
        return None, "scikit-learn not installed"
    sig = [v for v in views if v.is_signal]
    docs = [" ".join([v.event_type, v.signature or "", v.category or "", " ".join(sorted(v.tags)),
                      f"port{v.dport}", v.stage or "nostage"]) for v in sig]
    if len(docs) < 2:
        return [], "too few signal events"
    # Identical documents are clustered once and weighted (DBSCAN sample_weight): same result as
    # clustering every event, but memory stays bounded on 100k+ events with repetitive text.
    uniq: dict[str, int] = {}
    doc_idx = [uniq.setdefault(d, len(uniq)) for d in docs]
    weights = Counter(doc_idx)
    udocs = list(uniq)
    X = TfidfVectorizer(token_pattern=r"[A-Za-z0-9_]+").fit_transform(udocs)
    ulabels = DBSCAN(eps=0.3, min_samples=min_size, metric="cosine").fit_predict(
        X, sample_weight=[weights[i] for i in range(len(udocs))])
    groups = defaultdict(list)
    for v, i in zip(sig, doc_idx):
        l = ulabels[i]
        groups[f"c{l}" if l >= 0 else f"n{v.event_id}"].append(v.event_id)
    return list(groups.values()), "TF-IDF over event text (type, signature, tags, port, stage) + DBSCAN(cosine, eps=0.3)"


def run_evaluation(session: Session, dataset: Dataset, settings: AnalysisSettings, include_llm: bool = False,
                   models: list[str] | None = None, run: EvaluationRun | None = None) -> EvaluationRun:
    params = {"correlation": settings.correlation.model_dump(), "risk": settings.risk.model_dump(),
              "include_llm": include_llm, "models": models}
    if run is None:
        run = EvaluationRun(dataset_id=dataset.id, status="running", params=params)
        session.add(run)
    else:
        run.params = params
    session.flush()
    t_all = time.perf_counter()
    labels = dataset.labels or None
    timings = {}

    t0 = time.perf_counter()
    views = load_views(session, dataset.id)
    timings["load_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    catalog = get_catalog()
    t0 = time.perf_counter()
    run_detectors(views, settings.correlation, catalog)
    timings["detectors_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    by_id = {v.event_id: v for v in views}
    n_events = len(views)
    signal_ids = {v.event_id for v in views if v.is_signal}
    min_size = settings.correlation.min_incident_events

    t0 = time.perf_counter()
    proposed = correlate(views, settings.correlation)
    timings["correlation_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    t0 = time.perf_counter()
    drafts = [build_incident(g, by_id, catalog, settings) for g in proposed.groups]
    timings["incident_build_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    timings["throughput_events_per_s"] = round(
        n_events / max(1e-6, (timings["detectors_ms"] + timings["correlation_ms"] + timings["incident_build_ms"]) / 1000), 1)

    methods: dict[str, list[list[str]]] = {
        "A_independent_alerts": baseline_independent(views),
        "B_rule_based_shared_ip": baseline_rule_based(views, settings.correlation),
        "proposed_evidence_aware": [g.event_ids for g in proposed.groups] + [[e] for e in proposed.unassigned if e in signal_ids],
    }
    semantic, semantic_note = _tfidf_dbscan(views, min_size)
    if semantic is not None:
        methods["C_tfidf_dbscan_semantic"] = semantic

    results = {
        "dataset": {"name": dataset.name, "version": dataset.version, "synthetic": dataset.synthetic,
                    "input_events": n_events, "signal_events": len(signal_ids)},
        "engine_version": ENGINE_VERSION,
        "attack_catalog": catalog.version,
        "ground_truth": {"available": bool(labels),
                         "version": labels.get("version") if labels else None,
                         "note": ("Labels shipped with the dataset; never read by the engine."
                                  if labels else "No labels for this dataset: only descriptive statistics are reported.")},
        "timings": timings,
        "methods": {},
        "semantic_experiment_note": semantic_note + "; embedding-based clustering not run (no local embedding model "
                                    "is bundled; would require an extra dependency and a fair, separately tuned comparison).",
    }
    for name, groups in methods.items():
        results["methods"][name] = _describe(name, groups, n_events, len(signal_ids), min_size)

    event_labels = _event_labels(session, dataset.id) if labels and labels.get("kind") == "event-labels" else None
    if event_labels is not None:
        results["ground_truth"]["note"] = ("Per-connection MITRE ATT&CK labels published with the dataset (UWF-ZeekData). "
                                           "Never read by detectors, correlation or scoring.")
        results["label_scores"] = _score_event_labels(methods, drafts, event_labels, signal_ids, min_size, results)
        results["scenario_scores"] = None
    elif labels:
        truth_events = labels.get("events", {})
        truth = {eid: lab.get("group") for eid, lab in truth_events.items() if eid in by_id}
        groups_meta = labels.get("groups", {})
        universe = set(truth) | signal_ids
        labelled_in_data = {e for e, g in truth.items() if g}
        for name, groups in methods.items():
            pred = _assignment(groups, min_size)
            m = results["methods"][name]
            m["grouping"] = pairwise_grouping(pred, truth, universe)
            omitted = [e for e in labelled_in_data if e not in pred and (truth_events[e].get("stage"))
                       and groups_meta.get(truth[e], {}).get("malicious")]
            m["labelled_malicious_events_not_in_any_incident"] = len(omitted)
            m["labelled_malicious_events"] = sum(1 for e in labelled_in_data if groups_meta.get(truth[e], {}).get("malicious"))
            # unrelated singletons (scenario C) must not be merged
            merged_c = 0
            for gid, meta in groups_meta.items():
                if meta.get("singleton"):
                    ids = [e for e, g in truth.items() if g == gid]
                    if any(e in pred for e in ids):
                        merged_c += 1
            m["unrelated_singletons_merged"] = merged_c
        results["scenario_scores"] = _score_scenarios(drafts, truth, groups_meta, catalog)
    else:
        results["scenario_scores"] = None

    if include_llm:
        results["llm"] = _evaluate_llm(session, dataset, settings, models)
    else:
        results["llm"] = {"run": False, "note": "LLM evaluation not requested for this run."}

    run.results = results
    run.duration_ms = round((time.perf_counter() - t_all) * 1000, 1)
    run.status = "completed"
    session.flush()
    return run


def _event_labels(session: Session, dataset_id: int) -> dict[str, tuple[bool, tuple[str, ...]]]:
    from app.models import EventLabel
    return {eid: (bool(mal), tuple(tac)) for eid, mal, tac in session.query(
        EventLabel.event_id, EventLabel.malicious, EventLabel.tactics).filter(EventLabel.dataset_id == dataset_id)}


def _score_event_labels(methods: dict, drafts, labels: dict, signal_ids: set[str], min_size: int,
                        results: dict) -> dict:
    """Scores against per-event ground truth (UWF-style labels).

    * detection – event level: positive = labelled malicious; predicted = grouped into an
      incident (method A: every signal event is its own triage item, so predicted = signal).
    * grouping  – pair-counting P/R/F1 where the truth cluster is the event's labelled tactic
      set: do incidents keep different labelled activities apart?
    * tactic agreement – per incident, ATT&CK tactics mapped by the engine vs. tactics
      labelled on its member events (set P/R over all incidents).
    """
    truth = {e: "+".join(sorted(t)) for e, (mal, t) in labels.items() if mal and t}
    malicious = set(truth)
    universe = signal_ids | malicious
    for name, groups in methods.items():
        m = results["methods"][name]
        pred = _assignment(groups, min_size) if name != "A_independent_alerts" else {e: e for e in signal_ids}
        flagged = set(pred)
        tp = len(flagged & malicious)
        fp = sum(1 for e in flagged if e in labels and not labels[e][0])
        fp_unlabelled = len(flagged - set(labels))
        fn = len(malicious - flagged)
        m["detection"] = {**prf(tp, fp + fp_unlabelled, fn),
                          "unit": "events (positive = labelled malicious; predicted = in an incident)"}
        m["grouping"] = pairwise_grouping(pred if name != "A_independent_alerts" else {}, truth, universe)
        m["labelled_malicious_events"] = len(malicious)
        m["labelled_malicious_events_not_in_any_incident"] = fn
        m["unrelated_singletons_merged"] = None
    per_tactic: dict[str, Counter] = defaultdict(Counter)
    prop_pred = _assignment(methods["proposed_evidence_aware"], min_size)
    for e, (mal, tac) in labels.items():
        if not mal:
            continue
        for t in tac:
            per_tactic[t]["events"] += 1
            per_tactic[t]["signal"] += int(e in signal_ids)
            per_tactic[t]["in_incident"] += int(e in prop_pred)
    tactic_rows = []
    for t, c in sorted(per_tactic.items(), key=lambda kv: -kv[1]["events"]):
        tactic_rows.append({"tactic": t, "events": c["events"], "signal": c["signal"], "in_incident": c["in_incident"],
                            "recall": round(c["in_incident"] / c["events"], 4) if c["events"] else None})
    ttp = tfp = tfn = 0
    inc_rows = []
    for d in drafts:
        lab_tac = Counter(t for e in d.event_ids if e in labels for t in labels[e][1])
        n_lab = sum(1 for e in d.event_ids if e in labels and labels[e][0])
        pred_tac = {m.tactic_name for m in d.mappings}
        exp_tac = set(lab_tac)
        a, b, c = set_prf(pred_tac, exp_tac)
        ttp, tfp, tfn = ttp + a, tfp + b, tfn + c
        if len(inc_rows) < 60:
            inc_rows.append({"title": d.title, "events": len(d.event_ids), "severity": d.severity,
                             "labelled_malicious": n_lab, "purity": round(n_lab / len(d.event_ids), 4),
                             "predicted_tactics": sorted(pred_tac), "labelled_tactics": [t for t, _ in lab_tac.most_common()]})
    inc_rows.sort(key=lambda r: -r["events"])
    benign_inc = sum(1 for d in drafts if not any(e in labels and labels[e][0] for e in d.event_ids))
    return {
        "labelled_events": len(labels), "labelled_malicious": len(malicious),
        "tactics": tactic_rows,
        "tactic_agreement": {**prf(ttp, tfp, tfn),
                             "unit": "tactic names per incident: engine ATT&CK mapping vs. labels of member events"},
        "incidents": inc_rows,
        "incidents_without_labelled_attack": benign_inc,
        "note": "UWF labels describe the attacker's intended tactic for each connection. Network metadata alone "
                "cannot reveal several of them (e.g. Persistence, Privilege Escalation over SMB), so low recall "
                "for those tactics is expected and is reported, not hidden.",
    }


def _score_scenarios(drafts, truth: dict, groups_meta: dict, catalog) -> dict:
    """Attack-chain, ATT&CK and benign-escalation scores per labelled group."""
    group_members = defaultdict(set)
    for e, g in truth.items():
        if g:
            group_members[g].add(e)
    rows = []
    chain_tp = chain_fp = chain_fn = 0
    tech_tp = tech_fp = tech_fn = 0
    tac_tp = tac_fp = tac_fn = 0
    order_ok = order_n = 0
    benign_total = benign_fp = 0
    for gid, meta in sorted(groups_meta.items()):
        if meta.get("singleton"):
            continue
        members = group_members.get(gid, set())
        best, overlap = None, 0
        for d in drafts:
            ov = len(members & set(d.event_ids))
            if ov > overlap:
                best, overlap = d, ov
        expected_stages = set(meta.get("expected_stages", []))
        expected_tech = {t.split(".")[0] for t in meta.get("expected_techniques", [])}
        # a technique can belong to several tactics (e.g. T1078); any one of them counts as the expected tactic
        tactic_options = [set(catalog.techniques[t].tactics) for t in expected_tech]
        acceptable_tac = set().union(*tactic_options) if tactic_options else set()
        row = {"group": gid, "description": meta.get("description"), "malicious": meta.get("malicious"),
               "labelled_events": len(members), "matched_incident_events": len(best.event_ids) if best else 0,
               "overlap": overlap}
        if best is None:
            row.update(detected=False)
            chain_fn += len(expected_stages)
            tech_fn += len(expected_tech)
            tac_fn += len(tactic_options)
            rows.append(row)
            continue
        pred_stages = {s.stage for s in best.stages if s.status != "NOT_OBSERVED"}
        tp, fp, fn = set_prf(pred_stages, expected_stages)
        chain_tp, chain_fp, chain_fn = chain_tp + tp, chain_fp + fp, chain_fn + fn
        oc = order_correct({s.stage: s.first_ts for s in best.stages}, meta.get("expected_stages", []))
        if oc is not None:
            order_n += 1
            order_ok += int(oc)
        pred_tech = {m.technique_id.split(".")[0] for m in best.mappings if m.technique_id}
        ttp, tfp, tfn = set_prf(pred_tech, expected_tech)
        tech_tp, tech_fp, tech_fn = tech_tp + ttp, tech_fp + tfp, tech_fn + tfn
        pred_tac = {m.tactic_id for m in best.mappings}
        atp = sum(1 for opts in tactic_options if opts & pred_tac)
        afn = len(tactic_options) - atp
        afp = len(pred_tac - acceptable_tac)
        tac_tp, tac_fp, tac_fn = tac_tp + atp, tac_fp + afp, tac_fn + afn
        escalated = None
        if not meta.get("malicious"):
            benign_total += 1
            escalated = SEVERITY_RANK[best.severity] >= SEVERITY_RANK["High"]
            benign_fp += int(escalated)
        within_expectation = None
        if meta.get("expected_max_severity"):
            within_expectation = SEVERITY_RANK[best.severity] <= SEVERITY_RANK[meta["expected_max_severity"]]
        elif meta.get("expected_min_severity"):
            within_expectation = SEVERITY_RANK[best.severity] >= SEVERITY_RANK[meta["expected_min_severity"]]
        row.update(detected=True, incident_severity=best.severity, risk_score=best.risk_score,
                   confidence=best.confidence, predicted_stages=sorted(pred_stages), expected_stages=sorted(expected_stages),
                   stage_order_correct=oc, predicted_techniques=sorted(pred_tech), expected_techniques=sorted(expected_tech),
                   benign_escalated_to_high=escalated, severity_within_expectation=within_expectation,
                   group_recall=round(overlap / len(members), 4) if members else None,
                   incident_purity=round(overlap / len(best.event_ids), 4))
        rows.append(row)
    return {
        "groups": rows,
        "attack_chain_stages": {**prf(chain_tp, chain_fp, chain_fn),
                                "unit": "stage presence per labelled group (matched incident = max event overlap)"},
        "stage_order_correct": {"correct": order_ok, "evaluated": order_n},
        "attack_techniques": {**prf(tech_tp, tech_fp, tech_fn),
                              "unit": "technique IDs normalised to parent technique (T1071.001 → T1071); exact technique match only"},
        "attack_tactics": {**prf(tac_tp, tac_fp, tac_fn),
                           "unit": "one expected tactic per expected technique (any of the technique's ATT&CK tactics matches)"},
        "benign": {"benign_groups_with_incident": benign_total, "escalated_to_high_or_critical": benign_fp,
                   "false_positive_rate": round(benign_fp / benign_total, 4) if benign_total else None,
                   "note": "Synthetic benign set is small (3 groups); rate is illustrative, not a real-world FP rate."},
    }


def _evaluate_llm(session: Session, dataset: Dataset, settings: AnalysisSettings, models: list[str] | None) -> dict:
    from app.llm import client
    from app.llm.fallback import build_fallback
    from app.llm.sanitize import build_incident_payload
    from app.llm.service import _members, run_model
    from app.llm.validate import parse_and_validate
    from app.models import Incident

    llm = settings.llm
    incidents = list(session.query(Incident).filter(Incident.dataset_id == dataset.id)
                     .order_by(Incident.risk_score.desc()).limit(8))
    out: dict = {"run": True, "incidents_evaluated": len(incidents), "models": {}}
    # deterministic fallback self-check (always runs)
    fb_valid = 0
    for inc in incidents:
        members = _members(session, inc)
        payload, _ = build_incident_payload(inc, members, llm.max_events_in_prompt)
        fb = build_fallback(payload)
        ok, errs = parse_and_validate(fb.model_dump_json(), payload, {e.event_id for e in members})
        fb_valid += int(ok is not None)
    out["fallback_valid_rate"] = round(fb_valid / len(incidents), 4) if incidents else None
    try:
        installed = [m["name"] for m in client.list_models(llm.ollama_base_url)]
    except client.OllamaUnavailable as exc:
        out["models"] = {}
        out["note"] = f"Live LLM evaluation not run: {exc}. Only the deterministic fallback was validated."
        return out
    wanted = models or [m for m in (llm.primary_model, llm.secondary_model) if m]
    for model in wanted:
        if model not in installed:
            out["models"][model] = {"status": "not installed", "installed_models": installed}
            continue
        stats = Counter()
        latencies, errors_seen = [], []
        for inc in incidents:
            members = _members(session, inc)
            payload, flags = build_incident_payload(inc, members, llm.max_events_in_prompt)
            res = run_model(payload, {e.event_id for e in members}, settings, model)
            stats["requests"] += 1
            stats["attempts"] += res["attempts"]
            if res["summary"] is not None:
                stats["valid"] += 1
            if res["error"]:
                stats["transport_errors"] += 1
            latencies.append(res["latency_ms"])
            errors_seen.extend(res["validation_errors"])
            if flags:
                stats["injection_incidents"] += 1
                stats["injection_resisted"] += int(res["summary"] is not None or
                                                   not any("embedded in log data" in e for e in res["validation_errors"]))
        kinds = Counter(e.split(":")[0].split(" (")[0][:60] for e in errors_seen)
        out["models"][model] = {
            "status": "evaluated", "requests": stats["requests"],
            "valid_structured_output_rate": round(stats["valid"] / stats["requests"], 4) if stats["requests"] else None,
            "mean_attempts": round(stats["attempts"] / stats["requests"], 2) if stats["requests"] else None,
            "latency_ms_median": sorted(latencies)[len(latencies) // 2] if latencies else None,
            "latency_ms_max": max(latencies) if latencies else None,
            "transport_errors": stats["transport_errors"],
            "validation_error_types": dict(kinds.most_common(10)),
            "injection_incidents": stats["injection_incidents"],
            "injection_outputs_without_compliance": stats["injection_resisted"],
            "note": "Unsupported-claim audit = automated validator checks (unknown IDs/IPs/techniques, stage "
                    "upgrades, over-claiming). Human usefulness/readability review is not automated.",
        }
    return out


def _copy_settings(s: AnalysisSettings) -> AnalysisSettings:  # pragma: no cover - helper for experiments
    return copy.deepcopy(s)
