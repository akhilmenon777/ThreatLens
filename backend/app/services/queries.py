"""Read-side queries shared by the API and report exports."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.attack_mapping.catalog import get_catalog
from app.correlation.model import STAGES
from app.llm.service import latest_valid
from app.models import (AISummary, AttackMapping, CorrelationRun, Dataset, Event, EventLabel, EventLink, Incident,
                        IncidentEvent, IngestionJob)
from app.schemas import (EventDetail, EventOut, IncidentDetail, IncidentListItem, MappingOut, NoteOut, StageOut,
                         StatusChangeOut, SummaryOut)

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def incident_list(session: Session, dataset_id: int, q: str | None = None, severity: list[str] | None = None,
                  status: list[str] | None = None, sensor: str | None = None, tactic: str | None = None,
                  technique: str | None = None, start: datetime | None = None, end: datetime | None = None,
                  sort: str = "risk_score", order: str = "desc", page: int = 1, page_size: int = 25):
    stmt = select(Incident).where(Incident.dataset_id == dataset_id)
    if q:
        like = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.id.ilike(like),
                              cast(Incident.entities, String).ilike(like)))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))
    if status:
        stmt = stmt.where(Incident.status.in_(status))
    if start:
        stmt = stmt.where(Incident.last_seen >= start)
    if end:
        stmt = stmt.where(Incident.first_seen <= end)
    if technique or tactic:
        sub = select(AttackMapping.incident_id)
        if technique:
            sub = sub.where(or_(AttackMapping.technique_id == technique, AttackMapping.technique_id.like(technique + ".%")))
        if tactic:
            sub = sub.where(or_(AttackMapping.tactic_id == tactic, AttackMapping.tactic_name == tactic))
        stmt = stmt.where(Incident.id.in_(sub))
    rows = list(session.scalars(stmt))
    if sensor:
        rows = [r for r in rows if sensor in r.sensors]
    key = {"risk_score": lambda i: i.risk_score, "confidence": lambda i: i.confidence,
           "first_seen": lambda i: i.first_seen, "last_seen": lambda i: i.last_seen,
           "event_count": lambda i: i.event_count, "id": lambda i: i.id, "status": lambda i: i.status,
           "severity": lambda i: -SEV_ORDER.index(i.severity) if i.severity in SEV_ORDER else 0,
           "title": lambda i: i.title.lower()}.get(sort, lambda i: i.risk_score)
    rows.sort(key=key, reverse=(order == "desc"))
    total = len(rows)
    start_i = (page - 1) * page_size
    return total, [IncidentListItem.model_validate(r) for r in rows[start_i:start_i + page_size]]


def summary_out(s: AISummary | None, incident: Incident) -> SummaryOut | None:
    if s is None:
        return None
    out = SummaryOut.model_validate(s)
    out.is_current = s.evidence_hash == incident.evidence_hash
    return out


def incident_detail(session: Session, incident: Incident) -> IncidentDetail:
    cat = get_catalog()
    summary = latest_valid(incident) or next((s for s in reversed(incident.summaries)), None)
    maps = []
    for m in incident.mappings:
        mo = MappingOut.model_validate(m)
        if m.technique_id and m.technique_id in cat.techniques:
            mo.url = cat.techniques[m.technique_id].url
        maps.append(mo)
    link_count = session.scalar(select(func.count()).select_from(EventLink).where(EventLink.incident_id == incident.id)) or 0
    return IncidentDetail(
        **IncidentListItem.model_validate(incident).model_dump(),
        description=incident.description, risk_breakdown=incident.risk_breakdown,
        confidence_breakdown=incident.confidence_breakdown, alternative_explanations=incident.alternative_explanations,
        correlation_notes=incident.correlation_notes or [],
        stages=[StageOut.model_validate(s) for s in incident.stages],
        mappings=maps, notes=[NoteOut.model_validate(n) for n in incident.notes],
        status_changes=[StatusChangeOut.model_validate(c) for c in incident.status_changes],
        summary=summary_out(summary, incident), link_count=link_count, run_id=incident.run_id)


def incident_label_summary(session: Session, incident: Incident) -> dict | None:
    """Dataset ground-truth labels of the incident's member events (display only)."""
    rows = session.execute(select(EventLabel.malicious, EventLabel.tactics)
                           .join(IncidentEvent, IncidentEvent.event_id == EventLabel.event_id)
                           .where(IncidentEvent.incident_id == incident.id,
                                  EventLabel.dataset_id == incident.dataset_id)).all()
    if not rows:
        return None
    tactics: Counter = Counter()
    mal = 0
    for m, t in rows:
        mal += int(bool(m))
        tactics.update(t)
    return {"labelled": len(rows), "malicious": mal, "benign": len(rows) - mal,
            "tactics": [{"tactic": k, "count": v} for k, v in tactics.most_common()]}


def _event_out(e: Event, incident_ids: list[str], stage: str | None = None, detail: bool = False):
    model = EventDetail if detail else EventOut
    out = model.model_validate(e)
    out.incident_ids = incident_ids
    out.stage = stage
    return out


def incident_events(session: Session, incident_id: str, page: int = 1, page_size: int = 100, stage: str | None = None):
    stmt = (select(Event, IncidentEvent.stage).join(IncidentEvent, IncidentEvent.event_id == Event.event_id)
            .where(IncidentEvent.incident_id == incident_id))
    if stage:
        stmt = stmt.where(IncidentEvent.stage == stage)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.execute(stmt.order_by(Event.timestamp_utc, Event.event_id)
                           .offset((page - 1) * page_size).limit(page_size)).all()
    return total, [_event_out(e, [incident_id], st) for e, st in rows]


def event_incidents(session: Session, event_ids: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    if not event_ids:
        return out
    for eid, iid in session.execute(select(IncidentEvent.event_id, IncidentEvent.incident_id)
                                    .where(IncidentEvent.event_id.in_(event_ids))):
        out[eid].append(iid)
    return out


def event_list(session: Session, dataset_id: int, q: str | None = None, sensor: str | None = None,
               event_type: str | None = None, ip: str | None = None, assigned: str | None = None,
               tagged: bool | None = None, warnings: bool | None = None, incident_id: str | None = None,
               page: int = 1, page_size: int = 50, label: str | None = None):
    stmt = select(Event).where(Event.dataset_id == dataset_id)
    if label:
        lab = select(EventLabel.event_id).where(EventLabel.dataset_id == dataset_id)
        if label == "malicious":
            lab = lab.where(EventLabel.malicious.is_(True))
        elif label == "benign":
            lab = lab.where(EventLabel.malicious.is_(False))
        else:
            lab = lab.where(cast(EventLabel.tactics, String).like(f'%"{label[:60]}"%'))
        stmt = stmt.where(Event.event_id.in_(lab))
    if q:
        like = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(Event.event_id.ilike(like), Event.alert_signature.ilike(like), Event.dns_query.ilike(like),
                              Event.http_host.ilike(like), Event.tls_server_name.ilike(like),
                              Event.http_user_agent.ilike(like), Event.source_ip.ilike(like),
                              Event.destination_ip.ilike(like)))
    if sensor:
        stmt = stmt.where(Event.source_sensor == sensor)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type)
    if ip:
        stmt = stmt.where(or_(Event.source_ip == ip, Event.destination_ip == ip))
    in_inc = select(IncidentEvent.event_id)
    if incident_id:
        stmt = stmt.where(Event.event_id.in_(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident_id)))
    if assigned == "yes":
        stmt = stmt.where(Event.event_id.in_(in_inc))
    elif assigned == "no":
        stmt = stmt.where(Event.event_id.not_in(in_inc))
    if tagged is True:
        stmt = stmt.where(func.json_array_length(Event.detector_tags) > 0)
    elif tagged is False:
        stmt = stmt.where(func.json_array_length(Event.detector_tags) == 0)
    if warnings is True:
        stmt = stmt.where(func.json_array_length(Event.normalization_warnings) > 0)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(session.scalars(stmt.order_by(Event.timestamp_utc, Event.event_id)
                                .offset((page - 1) * page_size).limit(page_size)))
    ids = [e.event_id for e in rows]
    incs = event_incidents(session, ids)
    labels = {r.event_id: {"malicious": r.malicious, "tactics": r.tactics, "techniques": r.techniques}
              for r in session.scalars(select(EventLabel).where(EventLabel.dataset_id == dataset_id,
                                                                EventLabel.event_id.in_(ids)))} if ids else {}
    out = []
    for e in rows:
        o = _event_out(e, incs.get(e.event_id, []))
        o.ground_truth = labels.get(e.event_id)
        out.append(o)
    return total, out


def event_detail(session: Session, event: Event) -> EventDetail:
    incs = event_incidents(session, [event.event_id]).get(event.event_id, [])
    st = session.scalar(select(IncidentEvent.stage).where(IncidentEvent.event_id == event.event_id))
    return _event_out(event, incs, st, detail=True)


_OV_CACHE: dict[tuple, dict] = {}


def overview(session: Session, ds: Dataset) -> dict:
    """Cached per (dataset, correlation run, ingestion job, last incident change, notes)."""
    key = (ds.id,
           session.scalar(select(func.max(CorrelationRun.id)).where(CorrelationRun.dataset_id == ds.id)),
           session.scalar(select(func.max(IngestionJob.id)).where(IngestionJob.dataset_id == ds.id)),
           session.scalar(select(func.max(Incident.updated_at)).where(Incident.dataset_id == ds.id)))
    if key not in _OV_CACHE:
        if len(_OV_CACHE) > 16:
            _OV_CACHE.clear()
        _OV_CACHE[key] = _overview(session, ds)
    return _OV_CACHE[key]


def _overview(session: Session, ds: Dataset) -> dict:
    n_events = session.scalar(select(func.count()).select_from(Event).where(Event.dataset_id == ds.id)) or 0
    incidents = list(session.scalars(select(Incident).where(Incident.dataset_id == ds.id)
                                     .options(selectinload(Incident.stages), selectinload(Incident.mappings))))
    in_inc = session.scalar(select(func.count(func.distinct(IncidentEvent.event_id)))
                            .join(Incident, Incident.id == IncidentEvent.incident_id)
                            .where(Incident.dataset_id == ds.id)) or 0
    n_signal = session.scalar(select(func.count()).select_from(Event).where(
        Event.dataset_id == ds.id, func.json_array_length(Event.detector_tags) > 0)) or 0
    run = session.scalars(select(CorrelationRun).where(CorrelationRun.dataset_id == ds.id, CorrelationRun.is_current.is_(True))
                          .order_by(CorrelationRun.id.desc())).first()
    last_job = session.scalars(select(IngestionJob).where(IngestionJob.dataset_id == ds.id)
                               .order_by(IngestionJob.finished_at.desc())).first()
    sev = Counter(i.severity for i in incidents)
    status = Counter(i.status for i in incidents)
    sensors = dict(session.execute(select(Event.source_sensor, func.count()).where(Event.dataset_id == ds.id)
                                   .group_by(Event.source_sensor)).all())
    # stage distribution split observed / inferred
    stage_dist = {s: {"OBSERVED": 0, "INFERRED": 0} for s in STAGES}
    for i in incidents:
        for st in i.stages:
            if st.status in ("OBSERVED", "INFERRED"):
                stage_dist[st.stage][st.status] += 1
    # timeline: events per hour (by sensor) and incident starts per hour
    from app.services.analytics import bucket_expr
    granularity, hour, _, _ = bucket_expr(session, ds.id)
    fmt = "%Y-%m-%dT%H:00:00" if granularity == "hour" else "%Y-%m-%dT00:00:00"
    ev_hours = session.execute(select(hour, Event.source_sensor, func.count()).where(Event.dataset_id == ds.id)
                               .group_by(hour, Event.source_sensor).order_by(hour)).all()
    timeline: dict[str, dict] = {}
    for h, sensor, c in ev_hours:
        timeline.setdefault(h, {"hour": h + "Z", "suricata": 0, "zeek": 0, "wazuh": 0, "aminer": 0,
                                  "incidents_started": 0, "signal": 0})[sensor] = c
    sig_hours = session.execute(select(hour, func.count()).where(Event.dataset_id == ds.id,
                                func.json_array_length(Event.detector_tags) > 0).group_by(hour)).all()
    for h, c in sig_hours:
        if h in timeline:
            timeline[h]["signal"] = c
    for i in incidents:
        h = i.first_seen.strftime(fmt)
        if h in timeline:
            timeline[h]["incidents_started"] += 1
    # tactic x internal host heatmap
    heat: dict[str, Counter] = defaultdict(Counter)
    for i in incidents:
        for host in i.entities.get("internal_hosts", [])[:30]:
            for m in i.mappings:
                heat[host][m.tactic_name] += 1
    hosts_sorted = sorted(heat, key=lambda h: -sum(heat[h].values()))[:15]
    tactics_present = sorted({t for h in heat.values() for t in h},
                             key=lambda t: next((v["order"] for v in get_catalog().tactics.values() if v["name"] == t), 99))
    triage_items = len(incidents) + (n_signal - in_inc)
    return {
        "dataset": {"id": ds.id, "name": ds.name, "version": ds.version, "synthetic": ds.synthetic},
        "totals": {
            "raw_events": n_events, "signal_events": n_signal, "incidents": len(incidents),
            "critical_high": sev.get("Critical", 0) + sev.get("High", 0),
            "events_in_incidents": in_inc, "unassigned_events": n_events - in_inc,
            "unassigned_signal_events": max(0, n_signal - in_inc), "triage_items": triage_items,
            "reduction_pct": round((n_events - len(incidents)) / n_events * 100, 2) if n_events else None,
            "triage_reduction_pct": round((n_signal - triage_items) / n_signal * 100, 2) if n_signal else None,
            "open_incidents": sum(v for k, v in status.items() if k not in ("resolved", "closed")),
        },
        "definitions": {
            "reduction_pct": "((raw events − incidents) / raw events) × 100. Raw events include benign context traffic, "
                             "so this number is large by construction.",
            "triage_reduction_pct": "Compared with reviewing every alert-bearing (signal) event individually: "
                                    "triage items = incidents + signal events left outside any incident.",
            "unassigned_events": "Events not part of any incident (context traffic and isolated alerts).",
        },
        "latest_ingestion": last_job.finished_at.isoformat() + "Z" if last_job and last_job.finished_at else None,
        "correlation_run": {"id": run.id, "finished_at": run.finished_at.isoformat() + "Z" if run.finished_at else None,
                            "duration_ms": run.duration_ms, "message": run.message} if run else None,
        "severity_distribution": [{"severity": s, "count": sev.get(s, 0)} for s in SEV_ORDER],
        "status_distribution": [{"status": s, "count": status.get(s, 0)} for s in
                                ["new", "in_progress", "escalated", "resolved", "closed"]],
        "sensor_distribution": [{"sensor": k, "count": v} for k, v in sorted(sensors.items())],
        "stage_distribution": [{"stage": s, **stage_dist[s]} for s in STAGES],
        "timeline": sorted(timeline.values(), key=lambda r: r["hour"]),
        "timeline_granularity": granularity,
        "heatmap": {"hosts": hosts_sorted, "tactics": tactics_present,
                    "cells": [{"host": h, "tactic": t, "count": heat[h][t]} for h in hosts_sorted for t in tactics_present if heat[h][t]]},
        "top_incidents": [IncidentListItem.model_validate(i).model_dump(mode="json")
                          for i in sorted(incidents, key=lambda i: -i.risk_score)[:5]],
    }


def attack_matrix(session: Session, ds: Dataset) -> dict:
    cat = get_catalog()
    rows = session.execute(select(AttackMapping, Incident.severity).join(Incident, Incident.id == AttackMapping.incident_id)
                           .where(Incident.dataset_id == ds.id)).all()
    cells: dict[tuple, dict] = {}
    for m, sev in rows:
        key = (m.tactic_id, m.technique_id or "")
        c = cells.setdefault(key, {"tactic_id": m.tactic_id, "technique_id": m.technique_id, "technique_name": m.technique_name,
                                   "incidents": [], "observed": 0, "inferred": 0, "max_confidence": 0.0, "methods": set(),
                                   "evidence_events": 0})
        c["incidents"].append(m.incident_id)
        c["observed" if m.status == "OBSERVED" else "inferred"] += 1
        c["max_confidence"] = max(c["max_confidence"], m.confidence)
        c["methods"].add(m.method)
        c["evidence_events"] += len(m.evidence_event_ids)
    tactics = []
    for tid, t in sorted(cat.tactics.items(), key=lambda kv: kv[1]["order"]):
        techs = []
        for tech in cat.techniques.values():
            if tid in tech.tactics:
                c = cells.get((tid, tech.id))
                techs.append({"id": tech.id, "name": tech.name, "url": tech.url,
                              "count": len(c["incidents"]) if c else 0,
                              "observed": c["observed"] if c else 0, "inferred": c["inferred"] if c else 0,
                              "max_confidence": round(c["max_confidence"], 2) if c else None,
                              "incidents": sorted(set(c["incidents"])) if c else [],
                              "methods": sorted(c["methods"]) if c else [],
                              "evidence_events": c["evidence_events"] if c else 0})
        techs.sort(key=lambda x: (-x["count"], x["id"]))
        tactics.append({"id": tid, "name": t["name"], "count": sum(x["count"] for x in techs), "techniques": techs})
    return {"version": cat.version, "coverage_note": cat.coverage_note, "tactics": tactics}
