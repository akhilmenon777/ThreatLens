"""Behavioural detectors over normalised network events.

Each detector adds a *tag* (and a one-line evidence string) to the events that
support it. Tags are investigation hints, not verdicts. Only fields that exist
in network telemetry are used: IPs, ports, connection state, bytes, durations,
DNS queries, Zeek ssh auth_success, Suricata/Zeek alert text – plus, for host
sources, the Wazuh rule description / groups and the AMiner detector name.

Tagged events are "signal" events; untagged events remain available as context
but are never used to create links.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from app.attack_mapping.catalog import Catalog
from app.core.config import CorrelationSettings
from app.correlation.model import EventView, is_internal

FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
SCAN_WINDOW = timedelta(minutes=15)
BRUTE_WINDOW = timedelta(hours=1)
SUCCESS_LOOKBACK = timedelta(hours=2)


def _add(ev: EventView, tag: str, evidence: str) -> None:
    ev.tags.add(tag)
    ev.tag_evidence.setdefault(tag, evidence)


def _windows(events: list[EventView], window: timedelta):
    """Yield maximal sliding-window slices over time-sorted events."""
    j = 0
    for i in range(len(events)):
        while events[i].ts - events[j].ts > window:
            j += 1
        yield events[j:i + 1]


HOST_TYPES = {"host_alert": "Wazuh", "anomaly_alert": "AMiner"}
WEB_ERROR = "web server 400 error code"
AUTH_FAIL_GROUPS = ("authentication_failed", "invalid_login", "authentication_failures")


def tag_signatures(events: list[EventView], catalog: Catalog) -> None:
    for ev in events:
        host = ev.event_type in HOST_TYPES
        if ev.event_type == "ids_alert":
            _add(ev, "ids_alert", f"Suricata alert: {ev.signature or 'unnamed'}")
        elif ev.event_type == "zeek_notice":
            _add(ev, "zeek_notice", f"Zeek notice: {ev.category or ev.signature}")
        elif not host:
            continue
        text = f"{ev.signature or ''} {ev.category or ''}"
        for rule in catalog.signature_rules:  # first matching rule wins
            if rule.pattern.search(text):
                tag = rule.tag
                if host and tag == "policy_signature":
                    break  # host alerts only become signal through a meaningful rule
                if host:  # Wazuh / AMiner alerts are signal only when a rule gives them meaning
                    _add(ev, ev.event_type, f"{HOST_TYPES[ev.event_type]} alert: {ev.signature or 'unnamed'}")
                if ev.event_type == "zeek_notice":
                    tag = {"scan_signature": "port_scan_notice",
                           "bruteforce_signature": "password_guessing_notice"}.get(tag, tag)
                _add(ev, tag, f"rule {rule.id} matched '{text.strip()[:120]}'")
                break


def _tag_dense_windows(evs: list[EventView], window: timedelta, key, threshold: int, tag: str, evidence) -> None:
    """Tag every event that lies in a time window (<= ``window``) whose events have at least
    ``threshold`` distinct ``key`` values. Linear time: two pointers + a counter, and each
    event is tagged at most once (the old version re-tagged per window: O(n·w))."""
    if len(evs) < threshold:
        return
    counts: Counter = Counter()
    j = 0
    tagged_upto = -1
    for i, e in enumerate(evs):
        counts[key(e)] += 1
        while e.ts - evs[j].ts > window:
            k = key(evs[j])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            j += 1
        if len(counts) >= threshold:
            text = evidence(len(counts))
            for x in range(max(j, tagged_upto + 1), i + 1):
                _add(evs[x], tag, text)
            tagged_upto = i


def tag_scans(events: list[EventView], cfg: CorrelationSettings) -> None:
    conns = [e for e in events if e.event_type == "connection" and e.src and e.dst]
    by_src: dict[str, list[EventView]] = defaultdict(list)
    for e in conns:
        by_src[e.src].append(e)
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e.ts)
        failed = [e for e in evs if (e.conn_state or "") in FAILED_STATES or (e.duration or 0) < 0.01]
        # host sweep: many distinct destination hosts with failed/short connections
        _tag_dense_windows(failed, SCAN_WINDOW, lambda e: e.dst, cfg.scan_min_targets, "host_sweep",
                           lambda n, src=src: f"{src} contacted {n} hosts within 15 min (mostly failed/short)")
        # port scan: many distinct ports on one host
        by_dst: dict[str, list[EventView]] = defaultdict(list)
        for e in evs:
            if e.dport is not None:
                by_dst[e.dst].append(e)
        for dst, devs in by_dst.items():
            _tag_dense_windows(devs, SCAN_WINDOW, lambda e: e.dport, cfg.scan_min_targets, "port_scan",
                               lambda n, src=src, dst=dst: f"{src} probed {n} ports on {dst} within 15 min")


def tag_service_bruteforce(events: list[EventView], cfg: CorrelationSettings) -> None:
    """Connection-only brute-force heuristic (no auth result needed): a burst of connections
    from one source to the same authentication-capable service on one host."""
    ports = set(cfg.auth_service_ports)
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == "connection" and e.src and e.dst and e.dport in ports:
            series[(e.src, e.dst, e.dport)].append(e)
    n_min = cfg.service_bruteforce_min_connections
    for (src, dst, port), evs in series.items():
        if len(evs) < n_min:
            continue
        evs.sort(key=lambda e: e.ts)
        j = 0
        tagged_upto = -1
        for i, e in enumerate(evs):
            while e.ts - evs[j].ts > BRUTE_WINDOW:
                j += 1
            if i - j + 1 >= n_min:
                text = f"{i - j + 1}+ connections {src} -> {dst}:{port} within 1 h (authentication-capable service)"
                for x in range(max(j, tagged_upto + 1), i + 1):
                    _add(evs[x], "service_bruteforce", text)
                tagged_upto = i


def tag_probe_bursts(events: list[EventView], cfg: CorrelationSettings) -> None:
    """High-rate connections from one source to one TCP service (web/vulnerability scanning,
    crawling, fuzzing). Auth services are handled by the brute-force heuristic; infrastructure
    protocols (DNS, NTP, NetBIOS, mDNS…) are excluded."""
    skip = set(cfg.auth_service_ports) | {53, 67, 68, 123, 137, 138, 5353, 5355}
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if (e.event_type == "connection" and e.src and e.dst and e.dport is not None and e.dport not in skip
                and (e.proto or "tcp") == "tcp"):
            series[(e.src, e.dst, e.dport)].append(e)
    n_min = cfg.probe_burst_min_connections
    for (src, dst, port), evs in series.items():
        if len(evs) < n_min:
            continue
        evs.sort(key=lambda e: e.ts)
        j = 0
        tagged_upto = -1
        for i, e in enumerate(evs):
            while e.ts - evs[j].ts > SCAN_WINDOW:
                j += 1
            if i - j + 1 >= n_min:
                text = f"{i - j + 1}+ connections {src} -> {dst}:{port} within 15 min (high-rate service probing)"
                for x in range(max(j, tagged_upto + 1), i + 1):
                    _add(evs[x], "probe_burst", text)
                tagged_upto = i


def tag_admin_fanout(events: list[EventView], cfg: CorrelationSettings) -> None:
    """Internal host reaching several internal hosts over remote-administration ports."""
    nets = cfg.internal_networks
    ports = set(cfg.admin_ports)
    by_src: dict[str, list[EventView]] = defaultdict(list)
    for e in events:
        if (e.event_type == "connection" and e.dport in ports and e.src and e.dst and e.src != e.dst
                and is_internal(e.src, nets) and is_internal(e.dst, nets)
                and "host_sweep" not in e.tags and "port_scan" not in e.tags      # scanning is not movement
                and ((e.bytes_sent or 0) + (e.bytes_received or 0)) > 0          # a session carried data
                and (e.conn_state or "") not in ("S0", "REJ", "OTH", "SH", "SHR", "RSTOS0", "RSTRH")):
            by_src[e.src].append(e)
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e.ts)
        _tag_dense_windows(evs, BRUTE_WINDOW, lambda e: e.dst, cfg.admin_fanout_min_hosts, "admin_fanout",
                           lambda n, src=src: f"{src} reached {n} internal hosts over remote-admin ports "
                                              f"(SMB/RPC/RDP/WinRM) within 1 h")


def tag_ssh(events: list[EventView], cfg: CorrelationSettings) -> None:
    ssh = sorted((e for e in events if e.event_type == "ssh_auth" and e.src and e.dst), key=lambda e: e.ts)
    by_uid = defaultdict(list)
    for e in events:
        if e.event_type == "connection" and e.flow_uid:
            by_uid[e.flow_uid].append(e)
    pairs: dict[tuple[str, str], list[EventView]] = defaultdict(list)
    for e in ssh:
        pairs[(e.src, e.dst)].append(e)
    for (src, dst), evs in pairs.items():
        fails = [e for e in evs if e.auth_success is False]
        brute_members: set[str] = set()
        for win in _windows(fails, BRUTE_WINDOW):
            if len(win) >= cfg.bruteforce_min_failures:
                for e in win:
                    if e.event_id not in brute_members:
                        brute_members.add(e.event_id)
                        _add(e, "ssh_bruteforce", f"{len(win)} failed SSH logins {src} -> {dst} within 1 h")
                        for c in by_uid.get(e.flow_uid or "", []):
                            _add(c, "ssh_bruteforce", f"connection carrying a failed SSH login ({e.event_id})")
        for e in evs:
            if e.auth_success is True:
                prior = [f for f in fails if timedelta(0) <= e.ts - f.ts <= SUCCESS_LOOKBACK]
                if len(prior) >= cfg.bruteforce_min_failures:
                    _add(e, "auth_success_after_failures",
                         f"successful SSH login {src} -> {dst} after {len(prior)} failures in the previous 2 h")
                    for c in by_uid.get(e.flow_uid or "", []):
                        _add(c, "auth_success_after_failures",
                             f"session of the successful login ({e.event_id}), duration {c.duration or 0:.0f}s")


def tag_beacons(events: list[EventView], cfg: CorrelationSettings) -> None:
    nets = cfg.internal_networks
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == "connection" and is_internal(e.src, nets) and e.dst and not is_internal(e.dst, nets):
            series[(e.src, e.dst, e.dport)].append(e)
    by_uid = defaultdict(list)
    for e in events:
        if e.flow_uid and e.event_type in ("tls_handshake", "http_request"):
            by_uid[e.flow_uid].append(e)
    for (src, dst, port), evs in series.items():
        if len(evs) < cfg.beacon_min_connections:
            continue
        evs.sort(key=lambda e: e.ts)
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < cfg.beacon_min_connections - 1:
            continue
        med = statistics.median(gaps)
        if med < 10:
            continue
        mad = statistics.median(abs(g - med) for g in gaps)
        jitter = mad / med
        if jitter <= cfg.beacon_max_jitter_ratio:
            ev_text = (f"{len(evs)} connections {src} -> {dst}:{port}, median interval {med:.0f}s, "
                       f"jitter {jitter:.1%}")
            for e in evs:
                _add(e, "beacon", ev_text)
                for x in by_uid.get(e.flow_uid or "", []):
                    _add(x, "beacon", f"TLS/HTTP record of a beacon-like connection ({e.event_id})")


def tag_transfers(events: list[EventView], cfg: CorrelationSettings) -> None:
    nets = cfg.internal_networks
    by_uid = defaultdict(list)
    for e in events:
        if e.flow_uid and e.event_type in ("tls_handshake", "http_request"):
            by_uid[e.flow_uid].append(e)
    for e in events:
        if (e.event_type in ("connection", "flow") and (e.bytes_sent or 0) >= cfg.exfil_min_bytes
                and is_internal(e.src, nets) and e.dst and not is_internal(e.dst, nets)):
            mb = (e.bytes_sent or 0) / 1e6
            _add(e, "large_outbound", f"{mb:,.0f} MB sent from {e.src} to external {e.dst}:{e.dport}")
            for x in by_uid.get(e.flow_uid or "", []):
                _add(x, "large_outbound", f"TLS/HTTP record of a large outbound transfer ({e.event_id})")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def tag_dns(events: list[EventView], cfg: CorrelationSettings) -> None:
    for e in events:
        if e.event_type != "dns_query" or not e.dns_query or e.sensor != "zeek":
            continue
        label = e.dns_query.split(".")[0]
        if len(label) >= cfg.dns_tunnel_min_label_len and _entropy(label) >= 3.5:
            _add(e, "dns_tunnel", f"DNS label of {len(label)} chars with entropy {_entropy(label):.2f} bits/char")


def tag_web_error_bursts(events: list[EventView], cfg: CorrelationSettings) -> None:
    """Host-log view of web scanning: many HTTP 4xx errors logged by one web server for one
    client within 15 min (dirb / WPScan / gobuster style wordlist scanning)."""
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == "host_alert" and e.src and e.dst and WEB_ERROR in (e.signature or "").lower():
            series[(e.src, e.dst)].append(e)
    n_min = cfg.web_error_burst_min_errors
    for (src, dst), evs in series.items():
        if len(evs) < n_min:
            continue
        evs.sort(key=lambda e: e.ts)
        j = 0
        tagged_upto = -1
        for i, e in enumerate(evs):
            while e.ts - evs[j].ts > SCAN_WINDOW:
                j += 1
            if i - j + 1 >= n_min:
                text = f"{i - j + 1}+ HTTP 4xx errors for client {src} on web server {dst} within 15 min (host log)"
                for x in range(max(j, tagged_upto + 1), i + 1):
                    _add(evs[x], "web_error_burst", text)
                tagged_upto = i


def tag_host_auth_failures(events: list[EventView], cfg: CorrelationSettings) -> None:
    """Repeated authentication failures logged by one host (Wazuh: sshd, PAM, dovecot, …)."""
    series: dict[tuple, list[EventView]] = defaultdict(list)
    for e in events:
        if e.event_type == "host_alert" and e.dst and any(g in (e.category or "") for g in AUTH_FAIL_GROUPS):
            series[(e.src or "?", e.dst)].append(e)
    for (src, dst), evs in series.items():
        evs.sort(key=lambda e: e.ts)
        for win in _windows(evs, BRUTE_WINDOW):
            if len(win) >= cfg.bruteforce_min_failures:
                who = "unknown source" if src == "?" else src
                for e in win:
                    _add(e, "host_bruteforce", f"{len(win)} authentication failures from {who} logged by {dst} within 1 h")


def run_detectors(events: list[EventView], cfg: CorrelationSettings, catalog: Catalog) -> dict[str, int]:
    for e in events:
        e.tags.clear()
        e.tag_evidence.clear()
    tag_signatures(events, catalog)
    tag_scans(events, cfg)
    tag_ssh(events, cfg)
    tag_service_bruteforce(events, cfg)
    tag_probe_bursts(events, cfg)
    tag_admin_fanout(events, cfg)
    tag_beacons(events, cfg)
    tag_transfers(events, cfg)
    tag_dns(events, cfg)
    tag_web_error_bursts(events, cfg)
    tag_host_auth_failures(events, cfg)
    counts: Counter = Counter()
    for e in events:
        counts.update(e.tags)
    return dict(counts)
