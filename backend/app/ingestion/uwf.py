"""UWF-ZeekData24 / UWF-ZeekDataFall22 CSV parser.

The University of West Florida datasets publish Zeek ``conn.log`` records as
Spark CSV parts with MITRE ATT&CK labels appended::

    community_id,conn_state,duration,history,src_ip_zeek,src_port_zeek,dest_ip_zeek,
    dest_port_zeek,local_orig,local_resp,missed_bytes,orig_bytes,orig_ip_bytes,orig_pkts,
    proto,resp_bytes,resp_ip_bytes,resp_pkts,service,ts,uid,datetime,
    label_tactic,label_technique,label_binary,label_cve

Every row is converted back to a Zeek conn record (``id.orig_h`` …) and parsed by
the normal Zeek parser, so it goes through exactly the same validation as any
other Zeek log. The ``label_*`` columns are split off **before** hashing and are
never stored in the event or its raw payload: they are ground truth for the
evaluation lab only. A connection that appears in several tactic files (the
dataset marks these ``Duplicate``) therefore becomes one event with several labels.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from app.normalization.schema import RecordRejected

LABEL_COLUMNS = ("label_tactic", "label_technique", "label_binary", "label_cve")
REQUIRED = ("src_ip_zeek", "dest_ip_zeek", "ts")
FIELD_MAP = {
    "src_ip_zeek": "id.orig_h", "src_port_zeek": "id.orig_p",
    "dest_ip_zeek": "id.resp_h", "dest_port_zeek": "id.resp_p",
}
INT_FIELDS = {"id.orig_p", "id.resp_p", "missed_bytes", "orig_bytes", "orig_ip_bytes", "orig_pkts",
              "resp_bytes", "resp_ip_bytes", "resp_pkts"}
FLOAT_FIELDS = {"duration", "ts"}
BOOL_FIELDS = {"local_orig", "local_resp"}
DROP = {"datetime"}  # derived from ts by the exporter; ts is authoritative
NULL_VALUES = {"", "-", "none", "None", "null"}


@dataclass
class Label:
    tactics: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)

    @property
    def malicious(self) -> bool:
        return bool(self.tactics)

    def merge(self, other: "Label") -> None:
        self.tactics |= other.tactics
        self.techniques |= other.techniques


def looks_like_uwf(text: str) -> bool:
    head = text.lstrip("﻿").split("\n", 1)[0].lower()
    return "src_ip_zeek" in head and "dest_ip_zeek" in head


def _num(v: str, kind: type) -> Any:
    try:
        f = float(v)
    except ValueError:
        return v  # left for the Zeek parser to flag
    return int(f) if kind is int else f


def row_to_zeek(row: dict[str, str]) -> tuple[dict[str, Any], Label]:
    rec: dict[str, Any] = {"_path": "conn"}
    for k, v in row.items():
        if k is None or k in LABEL_COLUMNS or k in DROP:
            continue
        v = (v or "").strip()
        if v in NULL_VALUES:
            continue
        key = FIELD_MAP.get(k, k)
        if key in INT_FIELDS:
            rec[key] = _num(v, int)
        elif key in FLOAT_FIELDS:
            rec[key] = _num(v, float)
        elif key in BOOL_FIELDS:
            rec[key] = v.lower() in ("true", "t", "1")
        else:
            rec[key] = v
    tactic = (row.get("label_tactic") or "").strip()
    technique = (row.get("label_technique") or "").strip()
    lab = Label()
    if tactic and tactic.lower() != "none":
        lab.tactics.add(tactic)
    if technique and technique.lower() not in ("none", "duplicate") and technique.upper().startswith("T"):
        lab.techniques.add(technique.upper())
    return rec, lab


def iter_records(text: str) -> Iterator[tuple[int, str, Any, Label | None]]:
    """Yield (line_number, raw_line, zeek_obj_or_exception, label)."""
    text = text.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(text))
    header = reader.fieldnames or []
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        yield 1, ",".join(header)[:500], RecordRejected(f"UWF CSV header lacks required columns {missing}"), None
        return
    lines = text.splitlines()
    for row in reader:
        n = reader.line_num
        raw = lines[n - 1] if 0 < n <= len(lines) else ""
        if None in row:  # more values than header columns
            yield n, raw, RecordRejected("CSV row has more columns than the header"), None
            continue
        try:
            rec, lab = row_to_zeek(row)
        except Exception as exc:  # noqa: BLE001 - defensive
            yield n, raw, RecordRejected(f"cannot convert CSV row: {type(exc).__name__}"), None
            continue
        yield n, raw, rec, lab
