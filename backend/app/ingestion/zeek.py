"""Zeek log parser – JSON (one object per line) and classic TSV (#fields header).

Supported log paths: conn, dns, http, ssl, ssh, notice, files. Other paths are
accepted as generic events (``zeek_<path>``) with endpoint fields when present.
Zeek records carry no alert severity or signature ID – they are left ``None``.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from app.normalization.schema import (NormalizedEvent, RecordRejected, canonical_json, clean_bool,
                                      clean_float, clean_int, clean_ip, clean_port, clean_text,
                                      make_ids, parse_timestamp, truncate_raw)

EVENT_TYPE_MAP = {
    "conn": "connection",
    "dns": "dns_query",
    "http": "http_request",
    "ssl": "tls_handshake",
    "tls": "tls_handshake",
    "ssh": "ssh_auth",
    "notice": "zeek_notice",
    "files": "file_transfer",
}

KNOWN_PATHS = set(EVENT_TYPE_MAP)


def guess_path(filename: str) -> str | None:
    base = filename.lower().rsplit("/", 1)[-1]
    for p in KNOWN_PATHS:
        if base.startswith(p + ".") or base == p or base.startswith(p + "_"):
            return p
    return None


def _first(v: Any) -> Any:
    if isinstance(v, list):
        return v[0] if v else None
    return v


def parse_record(obj: Any, path: str | None, ref: str, max_field: int, max_raw: int) -> NormalizedEvent:
    if not isinstance(obj, dict):
        raise RecordRejected("record is not a JSON object")
    path = (obj.get("_path") or path or "").strip()
    if not path:
        raise RecordRejected("cannot determine Zeek log type (no _path field and unrecognised filename)")
    w: list[str] = []
    ts = parse_timestamp(obj.get("ts"))
    g = obj.get

    src_ip = g("id.orig_h")
    dst_ip = g("id.resp_h")
    src_p = g("id.orig_p")
    dst_p = g("id.resp_p")
    if path == "notice":
        src_ip = src_ip or g("src")
        dst_ip = dst_ip or g("dst")
        dst_p = dst_p if dst_p is not None else g("p")
    if path == "files":
        src_ip = src_ip or _first(g("tx_hosts"))
        dst_ip = dst_ip or _first(g("rx_hosts"))

    content_hash, event_id = make_ids("zeek", path, obj)
    uid = g("uid") or g("fuid")
    sig = cat = None
    if path == "notice":
        sig = g("msg") or g("note")
        cat = g("note")

    user = None
    if path == "ssh" and isinstance(g("user"), str):  # only if a script logs it
        user = g("user")

    return NormalizedEvent(
        source_sensor="zeek",
        source_log=path,
        timestamp_utc=ts,
        event_type=EVENT_TYPE_MAP.get(path, f"zeek_{path}"[:40]),
        original_event_reference=ref,
        raw_payload=truncate_raw(canonical_json(obj), max_raw),
        source_record_id=str(uid) if uid else None,
        source_ip=clean_ip(src_ip, w, "id.orig_h"),
        source_port=clean_port(src_p, w, "id.orig_p"),
        destination_ip=clean_ip(dst_ip, w, "id.resp_h"),
        destination_port=clean_port(dst_p, w, "id.resp_p"),
        transport_protocol=(str(g("proto")).lower()[:16] if g("proto") not in (None, "-") else None),
        application_protocol=clean_text(g("service"), 32, w, "service"),
        destination_host=clean_text(g("host") or g("server_name"), max_field, w, "host"),
        user_identity=clean_text(user, 255, w, "user"),
        alert_signature=clean_text(sig, max_field, w, "msg"),
        alert_category=clean_text(cat, 255, w, "note"),
        connection_state=clean_text(g("conn_state"), 16, w, "conn_state"),
        bytes_sent=clean_int(g("orig_bytes") if path != "files" else g("total_bytes"), w, "orig_bytes"),
        bytes_received=clean_int(g("resp_bytes"), w, "resp_bytes"),
        duration=clean_float(g("duration"), w, "duration"),
        dns_query=clean_text(g("query"), max_field, w, "query"),
        http_host=clean_text(g("host"), max_field, w, "host") if path == "http" else None,
        http_uri=clean_text(g("uri"), max_field, w, "uri"),
        http_user_agent=clean_text(g("user_agent"), max_field, w, "user_agent"),
        tls_server_name=clean_text(g("server_name"), max_field, w, "server_name"),
        auth_success=clean_bool(g("auth_success")) if path == "ssh" else None,
        community_id=clean_text(g("community_id"), 80, w, "community_id"),
        flow_uid=str(uid) if uid else None,
        normalization_warnings=w,
        content_hash=content_hash,
        event_id=event_id,
    )


# --------------------------------------------------------------------------- #
def _convert_tsv(value: str, ztype: str, empty: str, unset: str, set_sep: str) -> Any:
    if value == unset:
        return None
    if value == empty:
        return [] if ztype.startswith(("set", "vector")) else ""
    if ztype.startswith(("set", "vector")):
        return value.split(set_sep)
    if ztype in ("count", "int", "port"):
        try:
            return int(value)
        except ValueError:
            return value
    if ztype in ("double", "interval", "time"):
        try:
            return float(value)
        except ValueError:
            return value
    if ztype == "bool":
        return value == "T"
    return value


def iter_records(text: str, filename: str) -> Iterator[tuple[int, str, Any | Exception, str | None]]:
    """Yield (line_number, raw_line, obj_or_exception, path). Auto-detects JSON vs TSV."""
    lines = text.splitlines()
    first = next((ln for ln in lines if ln.strip()), "")
    path = guess_path(filename)
    if first.startswith("#"):
        sep, set_sep, empty, unset = "\t", ",", "(empty)", "-"
        fields: list[str] | None = None
        types: list[str] = []
        for n, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    raw = line.split(" ", 1)[1].strip()
                    sep = raw.encode().decode("unicode_escape")
                elif line.startswith("#set_separator"):
                    set_sep = line.split(sep, 1)[1]
                elif line.startswith("#empty_field"):
                    empty = line.split(sep, 1)[1]
                elif line.startswith("#unset_field"):
                    unset = line.split(sep, 1)[1]
                elif line.startswith("#path"):
                    path = line.split(sep, 1)[1].strip()
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                elif line.startswith("#types"):
                    types = line.split(sep)[1:]
                continue
            if fields is None:
                yield n, line, RecordRejected("TSV data line before #fields header"), path
                continue
            parts = line.split(sep)
            if len(parts) != len(fields):
                yield n, line, RecordRejected(
                    f"TSV column count {len(parts)} does not match {len(fields)} header fields"), path
                continue
            obj = {f: _convert_tsv(v, types[i] if i < len(types) else "string", empty, unset, set_sep)
                   for i, (f, v) in enumerate(zip(fields, parts))}
            obj = {k: v for k, v in obj.items() if v is not None}
            yield n, line, obj, path
        return
    for n, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            yield n, line, RecordRejected(f"malformed JSON: {exc.msg} at column {exc.colno}"), path
            continue
        yield n, line, obj, path
