"""Suricata EVE JSON parser (one JSON object per line)."""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from app.normalization.schema import (NormalizedEvent, RecordRejected, canonical_json, clean_float,
                                      clean_int, clean_ip, clean_port, clean_text, make_ids,
                                      parse_timestamp, truncate_raw)

EVENT_TYPE_MAP = {
    "alert": "ids_alert",
    "dns": "dns_query",
    "http": "http_request",
    "tls": "tls_handshake",
    "flow": "flow",
    "ssh": "ssh_session",
    "anomaly": "protocol_anomaly",
    "fileinfo": "file_transfer",
}


def parse_record(obj: Any, ref: str, max_field: int, max_raw: int) -> NormalizedEvent:
    if not isinstance(obj, dict):
        raise RecordRejected("record is not a JSON object")
    etype = obj.get("event_type")
    if not isinstance(etype, str) or not etype:
        raise RecordRejected("missing event_type (not a Suricata EVE record?)")
    if etype == "stats":
        raise RecordRejected("stats records are not security events")
    w: list[str] = []
    ts = parse_timestamp(obj.get("timestamp"))
    if isinstance(obj.get("timestamp"), str) and not any(c in obj["timestamp"][-6:] for c in "+-Z"):
        w.append("timestamp had no timezone; assumed UTC")
    alert = obj.get("alert") if isinstance(obj.get("alert"), dict) else {}
    flow = obj.get("flow") if isinstance(obj.get("flow"), dict) else {}
    dns = obj.get("dns") if isinstance(obj.get("dns"), dict) else {}
    http = obj.get("http") if isinstance(obj.get("http"), dict) else {}
    tls = obj.get("tls") if isinstance(obj.get("tls"), dict) else {}

    if etype == "alert" and not alert.get("signature"):
        w.append("alert record without signature")

    dns_query = dns.get("rrname")
    if dns_query is None and isinstance(dns.get("queries"), list) and dns["queries"]:
        q0 = dns["queries"][0]
        dns_query = q0.get("rrname") if isinstance(q0, dict) else None

    content_hash, event_id = make_ids("suricata", etype, obj)
    flow_id = obj.get("flow_id")
    sev = clean_int(alert.get("severity"), w, "alert.severity") if alert else None
    return NormalizedEvent(
        source_sensor="suricata",
        source_log=etype,
        timestamp_utc=ts,
        event_type=EVENT_TYPE_MAP.get(etype, f"suricata_{etype}"[:40]),
        original_event_reference=ref,
        raw_payload=truncate_raw(canonical_json(obj), max_raw),
        source_record_id=str(flow_id) if flow_id is not None else None,
        source_ip=clean_ip(obj.get("src_ip"), w, "src_ip"),
        source_port=clean_port(obj.get("src_port"), w, "src_port"),
        destination_ip=clean_ip(obj.get("dest_ip"), w, "dest_ip"),
        destination_port=clean_port(obj.get("dest_port"), w, "dest_port"),
        transport_protocol=(str(obj["proto"]).lower()[:16] if obj.get("proto") else None),
        application_protocol=clean_text(obj.get("app_proto"), 32, w, "app_proto"),
        destination_host=clean_text(http.get("hostname") or tls.get("sni"), max_field, w, "host"),
        alert_signature=clean_text(alert.get("signature"), max_field, w, "alert.signature"),
        alert_signature_id=clean_int(alert.get("signature_id"), w, "alert.signature_id"),
        alert_category=clean_text(alert.get("category"), 255, w, "alert.category"),
        sensor_severity=sev,
        connection_state=clean_text(flow.get("state"), 16, w, "flow.state"),
        bytes_sent=clean_int(flow.get("bytes_toserver"), w, "flow.bytes_toserver"),
        bytes_received=clean_int(flow.get("bytes_toclient"), w, "flow.bytes_toclient"),
        duration=clean_float(flow.get("age"), w, "flow.age"),
        dns_query=clean_text(dns_query, max_field, w, "dns.rrname"),
        http_host=clean_text(http.get("hostname"), max_field, w, "http.hostname"),
        http_uri=clean_text(http.get("url"), max_field, w, "http.url"),
        http_user_agent=clean_text(http.get("http_user_agent"), max_field, w, "http.http_user_agent"),
        tls_server_name=clean_text(tls.get("sni"), max_field, w, "tls.sni"),
        community_id=clean_text(obj.get("community_id"), 80, w, "community_id"),
        flow_uid=str(flow_id) if flow_id is not None else None,
        normalization_warnings=w,
        content_hash=content_hash,
        event_id=event_id,
    )


def iter_records(text: str, filename: str) -> Iterator[tuple[int, str, Any | Exception]]:
    """Yield (line_number, raw_line, parsed_obj_or_exception)."""
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            yield n, line, json.loads(line)
        except json.JSONDecodeError as exc:
            yield n, line, RecordRejected(f"malformed JSON: {exc.msg} at column {exc.colno}")
