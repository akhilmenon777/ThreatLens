"""Dataset analytics for the dashboard: traffic profile of the active dataset (per source sensor:
Zeek / Suricata / Wazuh / AMiner) and, when
the dataset ships ground-truth labels (e.g. UWF-ZeekData24), the labelled ATT&CK
distribution and how much of it the detectors / incidents cover.

Labels are read here for *display and evaluation only*; they never influence
detection, correlation, scoring or summaries.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import String, case, cast, func, select
from sqlalchemy.orm import Session

from app.models import Dataset, Event, EventLabel, Incident, IncidentEvent

TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact"]


def bucket_expr(session: Session, dataset_id: int):
    """Pick hour or day buckets so the timeline stays readable for long captures."""
    lo, hi = session.execute(select(func.min(Event.timestamp_utc), func.max(Event.timestamp_utc))
                             .where(Event.dataset_id == dataset_id)).one()
    span_h = ((hi - lo).total_seconds() / 3600) if lo and hi else 0
    if span_h <= 72:
        return "hour", func.strftime("%Y-%m-%dT%H:00:00", Event.timestamp_utc), lo, hi
    return "day", func.strftime("%Y-%m-%dT00:00:00", Event.timestamp_utc), lo, hi


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


def _top(session: Session, ds_id: int, col, n: int = 10, extra=None):
    stmt = select(col, func.count()).where(Event.dataset_id == ds_id, col.is_not(None))
    if extra is not None:
        stmt = stmt.where(extra)
    return [{"key": k, "count": c} for k, c in session.execute(stmt.group_by(col).order_by(func.count().desc()).limit(n))]


_CACHE: dict[tuple, dict] = {}


def _state_key(session: Session, ds: Dataset) -> tuple:
    """Changes whenever events, labels or the correlation result of the dataset change."""
    from app.models import CorrelationRun, IngestionJob
    run = session.scalar(select(func.max(CorrelationRun.id)).where(CorrelationRun.dataset_id == ds.id))
    job = session.scalar(select(func.max(IngestionJob.id)).where(IngestionJob.dataset_id == ds.id))
    return ds.id, run, job


def analytics(session: Session, ds: Dataset) -> dict:
    key = _state_key(session, ds)
    if key not in _CACHE:
        if len(_CACHE) > 16:
            _CACHE.clear()
        _CACHE[key] = _analytics(session, ds)
    return _CACHE[key]


def _analytics(session: Session, ds: Dataset) -> dict:
    ds_id = ds.id
    n = session.scalar(select(func.count()).select_from(Event).where(Event.dataset_id == ds_id)) or 0
    gran, bucket, lo, hi = bucket_expr(session, ds_id)
    tot = session.execute(select(func.coalesce(func.sum(Event.bytes_sent), 0), func.coalesce(func.sum(Event.bytes_received), 0),
                                 func.count(func.distinct(Event.source_ip)), func.count(func.distinct(Event.destination_ip)))
                          .where(Event.dataset_id == ds_id)).one()
    n_signal = session.scalar(select(func.count()).select_from(Event).where(
        Event.dataset_id == ds_id, func.json_array_length(Event.detector_tags) > 0)) or 0
    in_inc_q = (select(IncidentEvent.event_id).join(Incident, Incident.id == IncidentEvent.incident_id)
                .where(Incident.dataset_id == ds_id))

    # ---------------------------------------------------------------- traffic profile
    timeline: dict[str, dict] = {}
    for b, c, sig in session.execute(
            select(bucket, func.count(), func.sum(case((func.json_array_length(Event.detector_tags) > 0, 1), else_=0)))
            .where(Event.dataset_id == ds_id).group_by(bucket).order_by(bucket)):
        timeline[b] = {"t": b + "Z", "events": c, "signal": int(sig or 0), "malicious": 0, "benign": 0}

    proto = _top(session, ds_id, Event.transport_protocol, 6)
    services = _top(session, ds_id, Event.application_protocol, 10)
    states = _top(session, ds_id, Event.connection_state, 12)
    ports = _top(session, ds_id, Event.destination_port, 12)
    talkers = _top(session, ds_id, Event.source_ip, 10)
    targets = _top(session, ds_id, Event.destination_ip, 10)
    by_bytes = [{"key": k, "bytes": int(b or 0)} for k, b in session.execute(
        select(Event.source_ip, func.sum(func.coalesce(Event.bytes_sent, 0) + func.coalesce(Event.bytes_received, 0)))
        .where(Event.dataset_id == ds_id, Event.source_ip.is_not(None)).group_by(Event.source_ip)
        .order_by(func.sum(func.coalesce(Event.bytes_sent, 0) + func.coalesce(Event.bytes_received, 0)).desc()).limit(8))]
    tags = Counter()
    for tl, c in session.execute(select(cast(Event.detector_tags, String), func.count()).where(
            Event.dataset_id == ds_id, func.json_array_length(Event.detector_tags) > 0)
            .group_by(cast(Event.detector_tags, String))):
        for t in json.loads(tl):
            tags[t] += c

    # ---------------------------------------------------------------- per source (sensor) breakdown
    tagged_s = func.json_array_length(Event.detector_tags) > 0
    inside_s = Event.event_id.in_(in_inc_q)
    sources = []
    has_lab = n_labels_any(session, ds_id)
    for sensor, cnt, sig, inside, mal, tp, first, last in session.execute(
            select(Event.source_sensor, func.count(), func.sum(case((tagged_s, 1), else_=0)),
                   func.sum(case((inside_s, 1), else_=0)),
                   func.sum(case((EventLabel.malicious.is_(True), 1), else_=0)),
                   func.sum(case((EventLabel.malicious.is_(True) & inside_s, 1), else_=0)),
                   func.min(Event.timestamp_utc), func.max(Event.timestamp_utc))
            .select_from(Event)
            .outerjoin(EventLabel, (EventLabel.event_id == Event.event_id) & (EventLabel.dataset_id == ds_id))
            .where(Event.dataset_id == ds_id).group_by(Event.source_sensor)
            .order_by(func.count().desc())):
        mal, tp, inside = int(mal or 0), int(tp or 0), int(inside or 0)
        sources.append({"sensor": sensor, "events": cnt, "signal": int(sig or 0), "in_incident": inside,
                        "malicious": mal, "detected": tp,
                        "recall": round(tp / mal, 4) if has_lab and mal else None,
                        "precision": round(tp / inside, 4) if has_lab and inside else None,
                        "first_seen": _iso(first), "last_seen": _iso(last)})
    top_alerts = [{"key": sig, "sensor": sen, "count": c} for sig, sen, c in session.execute(
        select(Event.alert_signature, Event.source_sensor, func.count())
        .where(Event.dataset_id == ds_id, Event.alert_signature.is_not(None))
        .group_by(Event.alert_signature, Event.source_sensor).order_by(func.count().desc()).limit(12))]

    # ---------------------------------------------------------------- ground truth
    gt = None
    n_labels = session.scalar(select(func.count()).select_from(EventLabel).where(EventLabel.dataset_id == ds_id)) or 0
    if n_labels:
        tagged_x = func.json_array_length(Event.detector_tags) > 0
        inside_x = Event.event_id.in_(in_inc_q)
        rows = session.execute(
            select(EventLabel.malicious, cast(EventLabel.tactics, String), cast(EventLabel.techniques, String),
                   tagged_x, inside_x, bucket, func.count())
            .join(Event, Event.event_id == EventLabel.event_id)
            .where(EventLabel.dataset_id == ds_id, Event.dataset_id == ds_id)
            .group_by(EventLabel.malicious, cast(EventLabel.tactics, String), cast(EventLabel.techniques, String),
                      tagged_x, inside_x, bucket)).all()
        per_tactic: dict[str, Counter] = defaultdict(Counter)
        per_tech: Counter = Counter()
        mal = ben = 0
        mal_tl: dict[str, Counter] = defaultdict(Counter)
        cm = Counter()  # confusion at event level: malicious label vs. "in an incident"
        for is_mal, tactics_s, techniques_s, tagged, inside, b, n_rows in rows:
            tactics, techniques = json.loads(tactics_s or "[]"), json.loads(techniques_s or "[]")
            if is_mal:
                mal += n_rows
                if b in timeline:
                    timeline[b]["malicious"] += n_rows
                for t in tactics:
                    c = per_tactic[t]
                    c["events"] += n_rows
                    c["tagged"] += n_rows if tagged else 0
                    c["in_incident"] += n_rows if inside else 0
                    mal_tl[b][t] += n_rows
                for t in techniques:
                    per_tech[t] += n_rows
                cm["tp" if inside else "fn"] += n_rows
            else:
                ben += n_rows
                if b in timeline:
                    timeline[b]["benign"] += n_rows
                cm["fp" if inside else "tn"] += n_rows
        tactic_rows = sorted(({"tactic": t, **dict(c)} for t, c in per_tactic.items()),
                             key=lambda r: TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99)
        for r in tactic_rows:
            for k in ("tagged", "in_incident"):
                r.setdefault(k, 0)
            r["coverage_pct"] = round(r["in_incident"] / r["events"] * 100, 1) if r["events"] else None
        tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn) if tp + fn else None
        gt = {
            "available": True, "labelled_events": n_labels, "malicious": mal, "benign": ben,
            "tactics": tactic_rows,
            "techniques": [{"technique": t, "count": c} for t, c in per_tech.most_common(15)],
            "detection": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                          "precision": round(prec, 4) if prec is not None else None,
                          "recall": round(rec, 4) if rec is not None else None,
                          "f1": round(2 * prec * rec / (prec + rec), 4) if prec and rec else None,
                          "unit": "events; positive = labelled malicious, predicted = member of an incident"},
            "tactic_timeline": [{"t": b + "Z", **dict(c)} for b, c in sorted(mal_tl.items())],
            "note": ds.labels.get("note") if isinstance(ds.labels, dict) else None,
        }

    return {
        "dataset": {"id": ds.id, "name": ds.name, "description": ds.description, "version": ds.version,
                    "synthetic": ds.synthetic},
        "totals": {"events": n, "signal_events": n_signal, "unique_sources": tot[2], "unique_destinations": tot[3],
                   "bytes_out": int(tot[0]), "bytes_in": int(tot[1]), "first_seen": _iso(lo), "last_seen": _iso(hi),
                   "span_hours": round((hi - lo).total_seconds() / 3600, 1) if lo and hi else 0},
        "granularity": gran,
        "timeline": list(timeline.values()),
        "protocols": proto, "services": services, "conn_states": states, "dest_ports": ports,
        "top_sources": talkers, "top_destinations": targets, "top_sources_by_bytes": by_bytes,
        "detector_tags": [{"tag": t, "count": c} for t, c in tags.most_common()],
        "sources": sources, "top_alerts": top_alerts,
        "ground_truth": gt or {"available": False},
    }


def n_labels_any(session: Session, ds_id: int) -> bool:
    return bool(session.scalar(select(EventLabel.event_id).where(EventLabel.dataset_id == ds_id).limit(1)))


def event_label(session: Session, dataset_id: int, event_id: str) -> dict | None:
    row = session.get(EventLabel, (dataset_id, event_id))
    if row is None:
        return None
    return {"malicious": row.malicious, "tactics": row.tactics, "techniques": row.techniques}
