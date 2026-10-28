"""Ingestion orchestration: detect format, parse, validate, dedupe, persist.

Malformed / invalid records are never dropped silently – each one becomes a
``RejectedRecord`` with its line number, reason and a truncated excerpt.
Duplicates (identical source record, same SHA-256) are counted, not stored twice.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings, get_env
from app.ingestion import ait, suricata, uwf, zeek
from app.models import Dataset, Event, EventLabel, IngestionJob, RejectedRecord
from app.normalization.schema import RecordRejected

MAX_REJECT_DETAILS = 500
UWF_LABEL_KIND = "event-labels"
_AIT_WINDOWS: dict | None = None


def ait_windows() -> dict:
    """Attack-phase windows from the bundled AIT-ADS labels.csv (empty if the file is missing)."""
    global _AIT_WINDOWS
    if _AIT_WINDOWS is None:
        path = get_env().data_dir / "ait" / "labels.csv"
        _AIT_WINDOWS = ait.load_phase_windows(path.read_text()) if path.exists() else {}
    return _AIT_WINDOWS


class IngestionError(Exception):
    pass


def detect_sensor(text: str, filename: str) -> str:
    name = filename.lower()
    if uwf.looks_like_uwf(text[:4096]):
        return "uwf"
    if ait.looks_like_ait(text[:20000]):
        return "ait"
    if "eve" in name or "suricata" in name:
        return "suricata"
    if zeek.guess_path(filename):
        return "zeek"
    for line in text.splitlines()[:20]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#separator") or line.startswith("#fields"):
            return "zeek"
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "event_type" in obj and ("src_ip" in obj or "timestamp" in obj):
                return "suricata"
            if "_path" in obj or "id.orig_h" in obj or "uid" in obj:
                return "zeek"
    raise IngestionError("Could not detect whether the file is Suricata EVE JSON, a Zeek log or a UWF-ZeekData "
                         "CSV. Choose the format explicitly.")


def ingest_text(session: Session, dataset: Dataset, text: str, filename: str, sensor: str,
                settings: AnalysisSettings, line_phases: dict[int, str] | None = None) -> IngestionJob:
    """``line_phases`` (AIT only): ground-truth attack phase per line number, from the bundled
    ``*.labels.json`` sidecar. Without it, AIT files are labelled by the phase time windows alone."""
    env = get_env()
    if sensor == "auto":
        sensor = detect_sensor(text, filename)
    if sensor not in ("suricata", "zeek", "uwf", "ait"):
        raise IngestionError(f"Unsupported sensor '{sensor}'")
    ait_kind = ait.looks_like_ait(text[:20000]) if sensor == "ait" else None
    if sensor == "ait" and ait_kind is None:
        raise IngestionError("File does not look like AIT-ADS Wazuh or AMiner alerts (JSON lines)")
    if sensor == "uwf" and not uwf.looks_like_uwf(text[:4096]):
        raise IngestionError("File does not look like a UWF-ZeekData CSV (expected src_ip_zeek / dest_ip_zeek columns)")

    is_tsv = sensor == "zeek" and text.lstrip().startswith("#")
    fmt = ("uwf-zeek-csv" if sensor == "uwf" else f"ait-{ait_kind}-json" if sensor == "ait"
           else ("zeek-tsv" if is_tsv else f"{sensor}-json"))
    job_sensor = {"uwf": "zeek", "ait": ait_kind}.get(sensor, sensor)
    job = IngestionJob(dataset_id=dataset.id, filename=filename[:255], sensor=job_sensor, file_format=fmt)
    session.add(job)
    session.flush()

    # duplicates are detected per dataset (same source record); event IDs are global,
    # so a record that already exists in ANOTHER dataset gets a dataset-scoped ID.
    in_dataset: dict[str, str] = dict(session.execute(
        select(Event.content_hash, Event.event_id).where(Event.dataset_id == dataset.id)).all())
    known = set(session.scalars(select(Event.event_id)).all())
    max_field = env.max_field_chars
    max_raw = settings.display.max_raw_payload_chars if settings.display.retain_raw_payload else 512
    rows: list[dict] = []
    rejects: list[RejectedRecord] = []

    def reject(line_no: int, raw: str, reason: str) -> None:
        job.rejected += 1
        if len(rejects) < MAX_REJECT_DETAILS:
            rejects.append(RejectedRecord(job_id=job.id, line_number=line_no, reason=reason[:500],
                                          raw_excerpt=raw[:500]))

    labels: dict[str, uwf.Label] = {}
    scenario = ait.scenario_from_name(filename) if sensor == "ait" else None
    ait_scenario = ait_windows().get(scenario) if scenario else None
    if sensor == "suricata":
        records = ((n, line, obj, None, None) for n, line, obj in suricata.iter_records(text, filename))
    elif sensor == "uwf":
        records = ((n, line, obj, "conn", lab) for n, line, obj, lab in uwf.iter_records(text))
    elif sensor == "ait":
        records = ((n, line, obj, ait_kind, None) for n, line, obj in ait.iter_records(text))
    else:
        records = ((n, line, obj, path, None) for n, line, obj, path in zeek.iter_records(text, filename))

    for n, line, obj, path, lab in records:
        job.total_records += 1
        if isinstance(obj, Exception):
            reject(n, line, str(obj))
            continue
        ref = f"{filename}:{n}"
        try:
            if sensor == "suricata":
                ev = suricata.parse_record(obj, ref, max_field, max_raw)
            elif sensor == "ait":
                ev = ait.parse_record(obj, path, ref, max_field, max_raw)
            else:
                ev = zeek.parse_record(obj, path, ref, max_field, max_raw)
        except RecordRejected as exc:
            reject(n, line, str(exc))
            continue
        except Exception as exc:  # defensive: never let one record kill the job
            reject(n, line, f"unexpected parser error: {type(exc).__name__}")
            continue
        if ev.source_ip is None and ev.destination_ip is None and ev.event_type != "zeek_notice":
            reject(n, line, "record has no valid source or destination IP")
            continue
        if sensor == "ait" and (line_phases is not None or ait_scenario is not None):
            phase = line_phases.get(n) if line_phases is not None else ait.phase_at(ev.timestamp_utc, ait_scenario)
            lab = uwf.Label()
            if phase:
                tactic, technique, _ = ait.PHASES.get(phase, (None, None, None))
                if tactic:
                    lab.tactics.add(tactic)
                    lab.techniques.add(technique)
        dup_of = in_dataset.get(ev.content_hash)
        if dup_of is None and ev.event_id in known:
            ev.event_id = "EV-" + hashlib.sha256(f"{dataset.id}|{ev.content_hash}".encode()).hexdigest()[:16]
        if lab is not None:  # ground truth kept apart from the event (evaluation only)
            labels.setdefault(dup_of or ev.event_id, uwf.Label()).merge(lab)
        if dup_of is not None:
            job.duplicates += 1
            continue
        in_dataset[ev.content_hash] = ev.event_id
        known.add(ev.event_id)
        if ev.normalization_warnings:
            job.with_warnings += 1
        row = ev.to_row()
        row.update(dataset_id=dataset.id, job_id=job.id, detector_tags=[], tag_evidence={})
        rows.append(row)
        job.accepted += 1

    if rows:
        session.bulk_insert_mappings(Event, rows)
    session.add_all(rejects)
    if labels:
        store_labels(session, dataset.id, labels)
        mark_labels(dataset, "ait" if sensor == "ait" else "uwf")
    job.status = "completed" if job.accepted else ("failed" if job.total_records else "empty")
    job.message = (f"{job.accepted} accepted, {job.rejected} rejected, {job.duplicates} duplicates"
                   + (f" (only first {MAX_REJECT_DETAILS} rejections stored in detail)"
                      if job.rejected > MAX_REJECT_DETAILS else ""))
    job.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.flush()
    return job


LABEL_SOURCES = {
    "uwf": "UWF-ZeekData24 per-connection MITRE ATT&CK labels",
    "ait": "AIT-ADS attack-phase time windows (labels.csv) mapped to ATT&CK",
}


def mark_labels(dataset: Dataset, source: str) -> None:
    """Record that the dataset carries ground-truth labels and from which publisher(s)."""
    cur = dict(dataset.labels or {})
    sources = list(cur.get("sources") or ([] if cur.get("kind") != UWF_LABEL_KIND else ["uwf"]))
    if source not in sources:
        sources.append(source)
    dataset.labels = {"kind": UWF_LABEL_KIND, "sources": sources,
                      "version": " + ".join(LABEL_SOURCES[s] for s in sources),
                      "note": "Ground truth from the dataset publishers; used for evaluation and display only, "
                              "never by detection."}


def store_labels(session: Session, dataset_id: int, labels: dict[str, "uwf.Label"]) -> None:
    """Upsert ground-truth labels; a connection seen in several tactic files keeps every label."""
    ids = list(labels)
    existing: dict[str, EventLabel] = {}
    for i in range(0, len(ids), 900):
        for row in session.scalars(select(EventLabel).where(EventLabel.dataset_id == dataset_id,
                                                            EventLabel.event_id.in_(ids[i:i + 900]))):
            existing[row.event_id] = row
    new_rows = []
    for eid, lab in labels.items():
        row = existing.get(eid)
        if row is not None:
            row.tactics = sorted(set(row.tactics) | lab.tactics)
            row.techniques = sorted(set(row.techniques) | lab.techniques)
            row.malicious = bool(row.tactics)
        else:
            new_rows.append({"dataset_id": dataset_id, "event_id": eid, "malicious": lab.malicious,
                             "tactics": sorted(lab.tactics), "techniques": sorted(lab.techniques)})
    if new_rows:
        session.bulk_insert_mappings(EventLabel, new_rows)
