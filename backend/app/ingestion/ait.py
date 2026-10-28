"""AIT Alert Data Set (AIT-ADS) parser: Wazuh, Suricata-via-Wazuh and AMiner alerts.

AIT-ADS (Landauer, Skopik, Wurzenberger 2023, Zenodo 10.5281/zenodo.8263181, CC BY 4.0) ships two
JSON-lines files per attack scenario:

* ``<scenario>_wazuh.json`` – Wazuh manager alerts. Three kinds of record are inside:
    - Suricata EVE alerts forwarded by Wazuh (``location`` ends in ``eve.json``, the EVE record
      is in ``data``) → parsed by the normal Suricata parser, sensor ``suricata``;
    - Suricata ``fast.log`` lines decoded by Wazuh's snort decoder (rule 20101 "IDS event.")
      → ``ids_alert`` events of sensor ``suricata`` (source log ``fast``);
    - every other Wazuh rule (web access errors, sshd, dovecot, audit, …) → ``host_alert``
      events of sensor ``wazuh``.
* ``<scenario>_aminer.json`` – logdata-anomaly-miner anomaly alerts → ``anomaly_alert`` events
  of sensor ``aminer``.

Only values present in the record are used. Host-alert IPs come from Wazuh's decoded fields
(``data.srcip`` / ``data.dstip``) and the reporting agent; AMiner client IPs are read from the
raw log line only for the two log formats whose layout is fixed (Apache access and dnsmasq).
Ground-truth labels are NOT in these files: they come from the dataset's ``labels.csv`` (attack
phase time windows per scenario) and are attached by the ingestion service, never by the parser.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

from app.ingestion import suricata
from app.normalization.schema import (NormalizedEvent, RecordRejected, canonical_json, clean_int, clean_ip,
                                      clean_port, clean_text, make_ids, parse_timestamp, truncate_raw)

SCENARIOS = ("fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson")

# AIT-ADS attack phases -> ATT&CK tactic / technique (the label file names phases, not techniques)
PHASES: dict[str, tuple[str, str, str]] = {
    # phase: (tactic, technique, plain-language name)
    "network_scans": ("Reconnaissance", "T1595.001", "Network scan (nmap)"),
    "service_scans": ("Reconnaissance", "T1595.002", "Service / vulnerability scan (nmap)"),
    "dirb": ("Reconnaissance", "T1595.003", "Web directory brute force (dirb)"),
    "wpscan": ("Reconnaissance", "T1595.002", "WordPress vulnerability scan (WPScan)"),
    "webshell": ("Initial Access", "T1190", "Webshell upload via CVE-2020-24186"),
    "cracking": ("Credential Access", "T1110.002", "Password hash cracking (John the Ripper)"),
    "reverse_shell": ("Execution", "T1059.004", "Reverse shell"),
    "privilege_escalation": ("Privilege Escalation", "T1548.003", "Privilege escalation (sudo)"),
    "service_stop": ("Impact", "T1489", "Service stop"),
    "dnsteal": ("Exfiltration", "T1048.003", "DNS exfiltration (DNSteal)"),
}

_FAST = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<sig>.*?)\s*\[\*\*\]"
    r"(?:\s*\[Classification:\s*(?P<cls>[^\]]*)\])?(?:\s*\[Priority:\s*(?P<prio>\d+)\])?"
    r"\s*\{(?P<proto>[A-Za-z0-9-]+)\}\s*(?P<src>[0-9a-fA-F:.]+?)(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?::(?P<dport>\d+))?\s*$")
_APACHE = re.compile(r"^(?:(?P<vhost>\S+:\d+)\s+)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+"
                     r"\"(?P<method>[A-Z]+)\s+(?P<uri>\S+)[^\"]*\"\s+(?P<status>\d{3})")
_DNSMASQ = re.compile(r"query\[[A-Z0-9]+\]\s+(?P<q>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)")
_IP_PORT = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+?)(?::(?P<port>\d+))?$")


def wazuh_severity(level: Any) -> int | None:
    """Wazuh rule level 0-15 (higher = worse) mapped onto the Suricata-style 1 (high) .. 3 (low)
    scale used everywhere else; the native level stays in the raw payload / category."""
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return None
    return 1 if lv >= 12 else 2 if lv >= 7 else 3


def looks_like_ait(text: str) -> str | None:
    """Return 'wazuh' or 'aminer' when the first record looks like an AIT-ADS alert."""
    for line in text.splitlines()[:5]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if isinstance(obj, dict):
            if "AnalysisComponent" in obj and "LogData" in obj:
                return "aminer"
            if isinstance(obj.get("rule"), dict) and "agent" in obj and "@timestamp" in obj:
                return "wazuh"
        return None
    return None


def scenario_from_name(filename: str) -> str | None:
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for sc in SCENARIOS:
        if base.startswith(sc + "_"):
            return sc
    return None


def _split_ip_port(value: Any) -> tuple[Any, Any]:
    if not isinstance(value, str):
        return value, None
    m = _IP_PORT.match(value.strip())
    if m and value.count(":") <= 1:  # IPv4[:port]; leave IPv6 untouched
        return m.group("ip"), m.group("port")
    return value, None


def _parse_wazuh(obj: dict, ref: str, max_field: int, max_raw: int) -> NormalizedEvent:
    rule = obj.get("rule") if isinstance(obj.get("rule"), dict) else {}
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    agent = obj.get("agent") if isinstance(obj.get("agent"), dict) else {}
    pre = obj.get("predecoder") if isinstance(obj.get("predecoder"), dict) else {}
    location = str(obj.get("location") or "")
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []

    # 1) Suricata EVE alert forwarded by Wazuh: the EVE record is `data`
    if data.get("event_type") and ("suricata" in groups or location.endswith("eve.json")):
        ev = suricata.parse_record(data, ref, max_field, max_raw)
        ev.raw_payload = truncate_raw(canonical_json(obj), max_raw)
        return ev

    w: list[str] = []
    ts = parse_timestamp(obj.get("@timestamp"))

    # 2) Suricata fast.log line decoded by Wazuh (snort decoder)
    m = _FAST.search(str(obj.get("full_log") or "")) if location.endswith("fast.log") else None
    if m:
        content_hash, event_id = make_ids("suricata", "fast", obj)
        prio = clean_int(m.group("prio"), w, "priority")
        return NormalizedEvent(
            source_sensor="suricata", source_log="fast", timestamp_utc=ts, event_type="ids_alert",
            original_event_reference=ref, raw_payload=truncate_raw(canonical_json(obj), max_raw),
            source_record_id=clean_text(obj.get("id"), 64, w, "id"),
            source_ip=clean_ip(m.group("src"), w, "src_ip"), source_port=clean_port(m.group("sport"), w, "src_port"),
            destination_ip=clean_ip(m.group("dst"), w, "dest_ip"),
            destination_port=clean_port(m.group("dport"), w, "dest_port"),
            transport_protocol=m.group("proto").lower()[:16],
            alert_signature=clean_text(m.group("sig"), max_field, w, "signature"),
            alert_signature_id=clean_int(m.group("sid"), w, "signature_id"),
            alert_category=clean_text(m.group("cls"), 255, w, "classification"),
            sensor_severity=min(prio, 3) if prio else None,
            normalization_warnings=w, content_hash=content_hash, event_id=event_id)

    # 3) Wazuh host alert
    if not rule.get("description"):
        w.append("Wazuh alert without rule description")
    src, sport = _split_ip_port(data.get("srcip"))
    dst, dport = _split_ip_port(data.get("dstip"))
    src_ip = clean_ip(src, w, "data.srcip")
    dst_ip = clean_ip(dst, w, "data.dstip") or clean_ip(agent.get("ip"), w, "agent.ip")
    user = data.get("dstuser") or data.get("srcuser") or data.get("user")
    if isinstance(user, str):
        user = user.strip("<>") or None
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    category = ",".join(str(g) for g in groups[:8])
    if mitre.get("id"):
        category += " | ATT&CK " + ",".join(str(x) for x in mitre["id"][:4])
    content_hash, event_id = make_ids("wazuh", location or "alerts", obj)
    log_name = location.rsplit("/", 1)[-1] or "alerts"
    return NormalizedEvent(
        source_sensor="wazuh", source_log=log_name[:64], timestamp_utc=ts, event_type="host_alert",
        original_event_reference=ref, raw_payload=truncate_raw(canonical_json(obj), max_raw),
        source_record_id=clean_text(obj.get("id"), 64, w, "id"),
        source_ip=src_ip, source_port=clean_port(data.get("srcport") or sport, w, "data.srcport"),
        destination_ip=dst_ip, destination_port=clean_port(data.get("dstport") or dport, w, "data.dstport"),
        transport_protocol=clean_text(data.get("protocol"), 16, w, "data.protocol") if str(data.get("protocol", "")).lower() in ("tcp", "udp", "icmp") else None,
        destination_host=clean_text(pre.get("hostname"), max_field, w, "predecoder.hostname"),
        user_identity=clean_text(user, 128, w, "user"),
        alert_signature=clean_text(rule.get("description"), max_field, w, "rule.description"),
        alert_signature_id=clean_int(rule.get("id"), w, "rule.id"),
        alert_category=clean_text(f"level {rule.get('level')} · {category}", 255, w, "rule.groups"),
        sensor_severity=wazuh_severity(rule.get("level")),
        http_uri=clean_text(data.get("url"), max_field, w, "data.url"),
        normalization_warnings=w, content_hash=content_hash, event_id=event_id)


def _parse_aminer(obj: dict, ref: str, max_field: int, max_raw: int) -> NormalizedEvent:
    ac = obj.get("AnalysisComponent") if isinstance(obj.get("AnalysisComponent"), dict) else {}
    ld = obj.get("LogData") if isinstance(obj.get("LogData"), dict) else {}
    am = obj.get("AMiner") if isinstance(obj.get("AMiner"), dict) else {}
    w: list[str] = []
    stamps = ld.get("Timestamps") if isinstance(ld.get("Timestamps"), list) else []
    if not stamps:
        raise RecordRejected("AMiner alert without LogData.Timestamps")
    ts = parse_timestamp(stamps[0])
    raw_lines = ld.get("RawLogData") if isinstance(ld.get("RawLogData"), list) else []
    raw0 = str(raw_lines[0]) if raw_lines else ""
    resources = ld.get("LogResources") if isinstance(ld.get("LogResources"), list) else []
    resource = str(resources[0]) if resources else ""
    src_ip = uri = dns_q = None
    if (m := _APACHE.match(raw0)):
        src_ip, uri = m.group("ip"), m.group("uri")
    elif (m := _DNSMASQ.search(raw0)):
        src_ip, dns_q = m.group("ip"), m.group("q")
    content_hash, event_id = make_ids("aminer", resource or "aminer", obj)
    return NormalizedEvent(
        source_sensor="aminer", source_log=(resource.rsplit("/", 1)[-1] or "aminer")[:64], timestamp_utc=ts,
        event_type="anomaly_alert", original_event_reference=ref,
        raw_payload=truncate_raw(canonical_json(obj), max_raw),
        source_ip=clean_ip(src_ip, w, "log client ip"),
        destination_ip=clean_ip(am.get("ID"), w, "AMiner.ID"),
        alert_signature=clean_text(ac.get("AnalysisComponentName") or ac.get("Message"), max_field, w, "component"),
        alert_category=clean_text(f"{ac.get('AnalysisComponentType', '')} · {ac.get('Message', '')}", 255, w, "type"),
        sensor_severity=3,
        http_uri=clean_text(uri, max_field, w, "request uri"),
        dns_query=clean_text(dns_q, max_field, w, "dns query"),
        normalization_warnings=w, content_hash=content_hash, event_id=event_id)


def parse_record(obj: Any, kind: str, ref: str, max_field: int, max_raw: int) -> NormalizedEvent:
    if not isinstance(obj, dict):
        raise RecordRejected("record is not a JSON object")
    if kind == "aminer":
        return _parse_aminer(obj, ref, max_field, max_raw)
    return _parse_wazuh(obj, ref, max_field, max_raw)


def phase_at(ts: datetime, windows: list[tuple[str, float, float]]) -> str | None:
    t = ts.replace(tzinfo=timezone.utc).timestamp()
    for phase, start, end in windows:
        if start <= t <= end:
            return phase
    return None


def load_phase_windows(text: str) -> dict[str, list[tuple[str, float, float]]]:
    out: dict[str, list[tuple[str, float, float]]] = {}
    for line in text.splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 4 and parts[0]:
            try:
                out.setdefault(parts[0], []).append((parts[1], float(parts[2]), float(parts[3])))
            except ValueError:
                continue
    return out


def iter_records(text: str) -> Iterator[tuple[int, str, Any]]:
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            yield n, line, json.loads(line)
        except json.JSONDecodeError as exc:
            yield n, line, RecordRejected(f"malformed JSON: {exc.msg} at column {exc.colno}")
