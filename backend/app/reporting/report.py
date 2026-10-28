"""Incident and evaluation report exports (JSON, CSV, standalone HTML).

All untrusted strings are HTML-escaped. Reports state whether the data is
synthetic and carry the review disclaimer.
"""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

DISCLAIMER = ("Hypothesis, not proof of attack. Incidents are produced by automated correlation of network "
              "telemetry; AI-generated or templated narratives require analyst review. Network metadata cannot "
              "show payload content, process activity or user intent.")
LIMITATIONS = [
    "Only Suricata and Zeek network telemetry is analysed; no host or endpoint evidence.",
    "Detector thresholds and correlation weights are heuristic and configurable; scores are not calibrated probabilities.",
    "ATT&CK enrichment uses a partial local catalog subset.",
]


def _iso(d) -> str | None:
    if d is None:
        return None
    if isinstance(d, str):
        return d
    return d.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def incident_report_dict(detail: dict, events: list[dict], dataset: dict) -> dict:
    s = detail.get("summary") or {}
    return {
        "report_type": "incident",
        "generated_at": _iso(datetime.now(timezone.utc).replace(tzinfo=None)),
        "synthetic_data": dataset.get("synthetic", False),
        "dataset": {"name": dataset.get("name"), "version": dataset.get("version")},
        "incident": {k: detail[k] for k in ("id", "title", "description", "severity", "risk_score", "confidence",
                                             "first_seen", "last_seen", "event_count", "sensors", "entities", "status",
                                             "assignee", "suspected_false_positive")},
        "executive_summary": (s.get("content") or {}).get("executive_summary"),
        "summary_metadata": {k: s.get(k) for k in ("generator", "model", "model_version", "prompt_version", "status",
                                                    "created_at", "latency_ms")} if s else None,
        "summary": s.get("content") if s else None,
        "risk_breakdown": detail["risk_breakdown"],
        "confidence_breakdown": detail["confidence_breakdown"],
        "attack_chain": detail["stages"],
        "attack_mappings": detail["mappings"],
        "alternative_explanations": detail["alternative_explanations"],
        "timeline": events,
        "analyst_notes": detail["notes"],
        "status_history": detail["status_changes"],
        "disclaimer": DISCLAIMER,
        "limitations": LIMITATIONS,
    }


TIMELINE_COLS = ["timestamp_utc", "event_id", "source_sensor", "event_type", "stage", "source_ip", "source_port",
                 "destination_ip", "destination_port", "transport_protocol", "application_protocol", "alert_signature",
                 "dns_query", "tls_server_name", "bytes_sent", "detector_tags", "original_event_reference"]


def _csv_safe(v) -> str:
    s = "" if v is None else (";".join(map(str, v)) if isinstance(v, list) else str(v))
    if s[:1] in ("=", "+", "-", "@"):  # spreadsheet formula injection guard
        s = "'" + s
    return s


def incident_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["# incident", report["incident"]["id"], report["incident"]["title"],
                "SYNTHETIC DATA" if report["synthetic_data"] else "", DISCLAIMER])
    w.writerow(TIMELINE_COLS)
    for ev in report["timeline"]:
        w.writerow([_csv_safe(ev.get(c)) for c in TIMELINE_COLS])
    return buf.getvalue()


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def incident_html(r: dict) -> str:
    inc = r["incident"]
    s = r.get("summary") or {}
    meta = r.get("summary_metadata") or {}
    rows = "".join(
        f"<tr><td>{_e(ev.get('timestamp_utc'))}</td><td><code>{_e(ev.get('event_id'))}</code></td>"
        f"<td>{_e(ev.get('source_sensor'))}</td><td>{_e(ev.get('event_type'))}</td><td>{_e(ev.get('stage') or '')}</td>"
        f"<td>{_e(ev.get('source_ip'))}:{_e(ev.get('source_port'))} → {_e(ev.get('destination_ip'))}:{_e(ev.get('destination_port'))}</td>"
        f"<td>{_e(ev.get('alert_signature') or ev.get('dns_query') or ev.get('tls_server_name') or '')}</td></tr>"
        for ev in r["timeline"][:500])
    stages = "".join(
        f"<tr><td>{_e(st['stage'])}</td><td class='st {st['status']}'>{_e(st['status'])}</td>"
        f"<td>{_e(st.get('first_timestamp') or '')}</td><td>{_e(st['observed_behavior'])}</td><td>{_e(st['explanation'])}</td></tr>"
        for st in r["attack_chain"])
    maps = "".join(
        f"<tr><td>{_e(m['tactic_name'])} ({_e(m['tactic_id'])})</td><td>{_e(m.get('technique_name') or '—')} ({_e(m.get('technique_id') or 'tactic only')})</td>"
        f"<td class='st {m['status']}'>{_e(m['status'])}</td><td>{_e(m['method'])}</td><td>{m['confidence']:.2f}</td><td>{_e(m['reason'])}</td></tr>"
        for m in r["attack_mappings"])
    risk = "".join(f"<tr><td>{_e(b['label'])}</td><td>{b['points']}</td><td>{_e(b['explanation'])}</td></tr>"
                   for b in r["risk_breakdown"])
    conf = "".join(f"<tr><td>{_e(b['label'])}</td><td>{b.get('contribution', '')}</td><td>{_e(b['explanation'])}</td></tr>"
                   for b in r["confidence_breakdown"])
    li = lambda xs: "".join(f"<li>{_e(x)}</li>" for x in (xs or []))  # noqa: E731
    notes = "".join(f"<li><b>{_e(n['author'])}</b> ({_e(n['created_at'])}): {_e(n['text'])}</li>" for n in r["analyst_notes"])
    seq = "".join(f"<li><b>{_e(x['stage'])}</b> [{_e(x['status'])}] {_e(x['description'])} "
                  f"<small>{_e(', '.join(x.get('evidence_event_ids', [])))}</small></li>" for x in s.get("probable_sequence", []))
    gen_label = ("AI-generated analysis — analyst review required" if meta.get("generator") == "llm"
                 else "Deterministic summary (no LLM) — analyst review required")
    synthetic = "<div class='banner'>SYNTHETIC DATA – generated for demonstration; not real telemetry.</div>" if r["synthetic_data"] else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident report {_e(inc['id'])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#0f172a}}
h1{{font-size:22px}}h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #cbd5e1;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border:1px solid #e2e8f0;padding:4px 6px;text-align:left;vertical-align:top}}
.banner{{background:#fef3c7;border:1px solid #f59e0b;padding:8px 12px;border-radius:6px;margin:8px 0}}
.warn{{background:#fee2e2;border:1px solid #ef4444;padding:8px 12px;border-radius:6px}}.st.OBSERVED{{color:#0369a1;font-weight:600}}
.st.INFERRED{{color:#b45309;font-style:italic}}.st.NOT_OBSERVED{{color:#64748b}}code{{font-size:11px}}</style></head><body>
{synthetic}<h1>{_e(inc['id'])} — {_e(inc['title'])}</h1>
<p><b>Severity:</b> {_e(inc['severity'])} · <b>Risk:</b> {inc['risk_score']:.1f}/100 · <b>Correlation confidence:</b> {inc['confidence']:.2f} (heuristic, not a probability)
· <b>Status:</b> {_e(inc['status'])}{' · <b>Suspected false positive</b>' if inc['suspected_false_positive'] else ''} · <b>Assignee:</b> {_e(inc['assignee'] or '—')}</p>
<p><b>Window:</b> {_e(inc['first_seen'])} → {_e(inc['last_seen'])} · <b>Events:</b> {inc['event_count']} · <b>Sensors:</b> {_e(', '.join(inc['sensors']))}</p>
<p class="warn"><b>Hypothesis, not proof of attack.</b> {gen_label}.</p>
<h2>Executive summary</h2><p>{_e(r.get('executive_summary') or 'No summary generated.')}</p>
<p><small>Generator: {_e(meta.get('generator'))} · model {_e(meta.get('model'))} · prompt {_e(meta.get('prompt_version'))} · status {_e(meta.get('status'))} · generated {_e(meta.get('created_at'))}</small></p>
<h2>Probable sequence</h2><ul>{seq}</ul>
<h2>Attack chain (observed vs inferred)</h2><table><tr><th>Stage</th><th>Status</th><th>First seen</th><th>Behaviour</th><th>Explanation</th></tr>{stages}</table>
<h2>ATT&amp;CK mappings</h2><table><tr><th>Tactic</th><th>Technique</th><th>Status</th><th>Method</th><th>Confidence</th><th>Reason</th></tr>{maps}</table>
<h2>Risk breakdown</h2><table><tr><th>Factor</th><th>Points</th><th>Detail</th></tr>{risk}</table>
<h2>Correlation confidence</h2><table><tr><th>Factor</th><th>Contribution</th><th>Detail</th></tr>{conf}</table>
<h2>Alternative explanations</h2><ul>{li(r['alternative_explanations'])}</ul>
<h2>Missing evidence</h2><ul>{li(s.get('missing_evidence'))}</ul>
<h2>Analyst notes</h2><ul>{notes or '<li>None</li>'}</ul>
<h2>Timeline / supporting evidence ({len(r['timeline'])} events{', first 500 shown' if len(r['timeline']) > 500 else ''})</h2>
<table><tr><th>Time (UTC)</th><th>Event</th><th>Sensor</th><th>Type</th><th>Stage</th><th>Endpoints</th><th>Detail</th></tr>{rows}</table>
<h2>Limitations</h2><ul>{li(r['limitations'])}</ul><p><small>{_e(r['disclaimer'])}</small></p>
<p><small>Generated {_e(r['generated_at'])} · dataset {_e(r['dataset']['name'])} v{_e(r['dataset']['version'])}</small></p></body></html>"""


def evaluation_markdown(run: dict) -> str:
    r = run["results"]
    lines = [f"# Evaluation run {run['id']}", "",
             f"- Dataset: {r['dataset']['name']} ({r['dataset']['version']}, {'SYNTHETIC' if r['dataset']['synthetic'] else 'real / uploaded'})",
             f"- Input events: {r['dataset']['input_events']} · signal events: {r['dataset']['signal_events']}",
             f"- Engine: {r['engine_version']} · ATT&CK catalog: {r['attack_catalog']}",
             f"- Ground truth: {'available (' + str(r['ground_truth']['version']) + ')' if r['ground_truth']['available'] else 'not available'} – {r['ground_truth']['note']}",
             f"- Run at: {run['created_at']} · duration {run['duration_ms']:.0f} ms", "",
             "## Correlation methods", "",
             "| Method | Incidents | Triage items | Triage reduction vs A | Pairwise P | R | F1 | Unrelated alerts merged |",
             "|---|---|---|---|---|---|---|---|"]
    for name, m in r["methods"].items():
        g = m.get("grouping") or {}
        lines.append(f"| {name} | {m['incidents']} | {m['triage_items']} | {m['triage_reduction_vs_independent_pct']}% | "
                     f"{g.get('precision', '–')} | {g.get('recall', '–')} | {g.get('f1', '–')} | {m.get('unrelated_singletons_merged', '–')} |")
    sc = r.get("scenario_scores")
    if sc:
        lines += ["", "## Proposed method – scenario scores", "",
                  f"- Attack-chain stages: P {sc['attack_chain_stages']['precision']} R {sc['attack_chain_stages']['recall']} F1 {sc['attack_chain_stages']['f1']}",
                  f"- ATT&CK techniques: P {sc['attack_techniques']['precision']} R {sc['attack_techniques']['recall']} F1 {sc['attack_techniques']['f1']}",
                  f"- ATT&CK tactics: P {sc['attack_tactics']['precision']} R {sc['attack_tactics']['recall']} F1 {sc['attack_tactics']['f1']}",
                  f"- Benign groups escalated to High/Critical: {sc['benign']['escalated_to_high_or_critical']} of {sc['benign']['benign_groups_with_incident']}"]
    ls = r.get("label_scores")
    if ls:
        lines += ["", "## Detection against dataset labels (event level)", "",
                  "| Method | Precision | Recall | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
        for name, m in r["methods"].items():
            d = m.get("detection") or {}
            lines.append(f"| {name} | {d.get('precision', '–')} | {d.get('recall', '–')} | {d.get('f1', '–')} | "
                         f"{d.get('tp', '–')} | {d.get('fp', '–')} | {d.get('fn', '–')} |")
        ta = ls["tactic_agreement"]
        lines += ["", "### Labelled tactic coverage (proposed method)", "",
                  "| Tactic | Labelled events | Detector-tagged | In an incident | Recall |", "|---|---|---|---|---|"]
        lines += [f"| {t['tactic']} | {t['events']} | {t['signal']} | {t['in_incident']} | {t['recall']} |" for t in ls["tactics"]]
        lines += ["", f"- Tactic agreement (engine mapping vs labels): P {ta['precision']} R {ta['recall']} F1 {ta['f1']}",
                  f"- Incidents without any labelled attack event: {ls['incidents_without_labelled_attack']}", "", ls["note"]]
    lines += ["", "## Timings", "", "```", json.dumps(r["timings"], indent=1), "```", "", "## LLM", "", "```",
              json.dumps(r.get("llm"), indent=1), "```", ""]
    lines.append("Synthetic results demonstrate behaviour on designed scenarios; they are not real-world performance."
                 if r["dataset"]["synthetic"] else
                 "Results on lab-generated, labelled traffic; heuristic thresholds were not tuned per dataset and "
                 "do not represent production performance.")
    return "\n".join(lines)
