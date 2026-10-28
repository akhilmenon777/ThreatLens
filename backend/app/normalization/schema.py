"""Common event schema (version 1.0) and normalization helpers.

Every parser produces ``NormalizedEvent`` objects. Unavailable values stay
``None`` – nothing is guessed (no invented users, hosts, PIDs or DNS names).
The untouched source record is kept in ``raw_payload``.

Field reference (also served at GET /api/schema):
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"

FIELD_DOCS: dict[str, str] = {
    "event_id": "Stable ID: 'EV-' + first 16 hex chars of SHA-256(sensor|log|canonical raw record)",
    "source_sensor": "suricata | zeek | wazuh | aminer",
    "source_log": "Suricata event_type or Zeek log path (conn, dns, http, ssl, ssh, notice, files)",
    "source_record_id": "Sensor-native identifier when present (Suricata flow_id, Zeek uid/fuid)",
    "timestamp_utc": "Event time normalised to UTC (naive datetime, UTC implied)",
    "event_type": "Normalised type: ids_alert, connection, dns_query, http_request, tls_handshake, ssh_auth, zeek_notice, file_transfer, flow, host_alert (Wazuh), anomaly_alert (AMiner), ...",
    "source_ip / destination_ip": "Validated IPv4/IPv6 strings",
    "source_port / destination_port": "0-65535",
    "transport_protocol": "tcp | udp | icmp | ...",
    "application_protocol": "Suricata app_proto or Zeek service",
    "source_host / destination_host": "Only when the record names a host (e.g. HTTP Host header, TLS SNI)",
    "user_identity": "Only when present in the record (e.g. Zeek ssh client user if logged)",
    "alert_signature / alert_signature_id / alert_category": "Suricata alert metadata, or Zeek notice note/msg",
    "sensor_severity": "Severity on the Suricata scale 1=high .. 3=low (Wazuh rule level >=12 -> 1, >=7 -> 2, else 3; AMiner 3; Zeek notices have none)",
    "connection_state": "Zeek conn_state (S0, REJ, SF, ...) or Suricata flow state",
    "bytes_sent / bytes_received": "Originator->responder and responder->originator payload bytes",
    "duration": "Seconds",
    "dns_query": "Queried name",
    "http_host / http_uri / http_user_agent": "HTTP metadata (untrusted text, length-limited)",
    "tls_server_name": "TLS SNI",
    "auth_success": "Zeek ssh.log auth_success when logged",
    "community_id": "Community ID flow hash when the sensor emits it (cross-sensor join key)",
    "flow_uid": "Zeek uid or Suricata flow_id",
    "original_event_reference": "file:line reference to the source record",
    "raw_payload": "Original record (JSON text), length-limited by settings",
    "normalization_warnings": "List of issues found while normalising (missing/invalid/truncated fields)",
}

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class RecordRejected(Exception):
    """Raised when a record cannot be normalised into a valid event."""


@dataclass
class NormalizedEvent:
    source_sensor: str
    source_log: str
    timestamp_utc: datetime
    event_type: str
    original_event_reference: str
    raw_payload: str
    source_record_id: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    transport_protocol: str | None = None
    application_protocol: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    user_identity: str | None = None
    alert_signature: str | None = None
    alert_signature_id: int | None = None
    alert_category: str | None = None
    sensor_severity: int | None = None
    connection_state: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    duration: float | None = None
    dns_query: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    http_user_agent: str | None = None
    tls_server_name: str | None = None
    auth_success: bool | None = None
    community_id: str | None = None
    flow_uid: str | None = None
    normalization_warnings: list[str] = field(default_factory=list)
    content_hash: str = ""
    event_id: str = ""

    def to_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["schema_version"] = SCHEMA_VERSION
        return d


# --------------------------------------------------------------------------- #
# helpers used by all parsers
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def make_ids(sensor: str, log: str, raw_obj: Any) -> tuple[str, str]:
    canon = canonical_json(raw_obj)
    content_hash = hashlib.sha256(f"{sensor}|{log}|{canon}".encode()).hexdigest()
    return content_hash, "EV-" + content_hash[:16]


def parse_timestamp(value: Any) -> datetime:
    """Accept ISO-8601 (with Z or offset, Suricata's +0000 form) or epoch seconds."""
    if value is None or value == "" or value == "-":
        raise RecordRejected("missing timestamp")
    if isinstance(value, bool):
        raise RecordRejected(f"invalid timestamp {value!r}")
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,11}(\.\d+)?", value)):
        try:
            ts = float(value)
        except ValueError as exc:
            raise RecordRejected(f"invalid timestamp {value!r}") from exc
        if not (0 < ts < 4102444800):  # before 2100
            raise RecordRejected(f"timestamp out of range {value!r}")
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    if not isinstance(value, str):
        raise RecordRejected(f"invalid timestamp type {type(value).__name__}")
    s = value.strip()
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # +0000 -> +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise RecordRejected(f"invalid timestamp {value!r}") from exc
    if dt.tzinfo is None:
        # Naive timestamps are assumed UTC; recorded as a warning by callers.
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def clean_text(value: Any, max_len: int, warnings: list[str], name: str) -> str | None:
    """Untrusted text: strip control chars, cap length, never interpret."""
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        value = canonical_json(value)
    s = str(value)
    if s in ("-", "(empty)"):
        return None
    cleaned = _CTRL.sub("", s)
    if cleaned != s:
        warnings.append(f"{name}: control characters removed")
    if len(cleaned) > max_len:
        warnings.append(f"{name}: truncated from {len(cleaned)} to {max_len} chars")
        cleaned = cleaned[:max_len]
    return cleaned


def clean_ip(value: Any, warnings: list[str], name: str) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        warnings.append(f"{name}: invalid IP {str(value)[:60]!r} dropped")
        return None


def clean_port(value: Any, warnings: list[str], name: str) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        p = int(value)
    except (TypeError, ValueError):
        warnings.append(f"{name}: invalid port {str(value)[:20]!r} dropped")
        return None
    if not 0 <= p <= 65535:
        warnings.append(f"{name}: port {p} out of range dropped")
        return None
    return p


def clean_int(value: Any, warnings: list[str], name: str) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        v = int(float(value))
    except (TypeError, ValueError):
        warnings.append(f"{name}: non-numeric value dropped")
        return None
    if v < 0:
        warnings.append(f"{name}: negative value dropped")
        return None
    return min(v, 2**62)


def clean_float(value: Any, warnings: list[str], name: str) -> float | None:
    if value in (None, "", "-"):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        warnings.append(f"{name}: non-numeric value dropped")
        return None
    return v if v >= 0 else None


def clean_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in ("T", "true", "True", 1, "1"):
        return True
    if value in ("F", "false", "False", 0, "0"):
        return False
    return None


def truncate_raw(raw: str, max_chars: int) -> str:
    return raw if len(raw) <= max_chars else raw[:max_chars] + "…[truncated]"
