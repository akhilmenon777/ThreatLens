from datetime import datetime, timedelta

from app.attack_chain.reconstruct import reconstruct
from app.attack_mapping.catalog import CatalogError, get_catalog
from app.attack_mapping.mapper import map_incident
from app.correlation.detectors import run_detectors
from app.correlation.engine import Group, baseline_rule_based, correlate, score_pair, _entities
from app.correlation.model import EventView
from app.risk.scoring import compute_confidence, compute_risk, severity_label

T0 = datetime(2026, 10, 20, 9, 0)
_n = 0


def ev(**kw) -> EventView:
    global _n
    _n += 1
    base = dict(event_id=f"EV-{_n:016x}", ts=T0, sensor="zeek", log="conn", event_type="connection", src=None, dst=None)
    base.update(kw)
    return EventView(**base)


def brute_force(src="192.168.56.9", dst="10.10.0.5", n=12, start=T0, success=False):
    out = [ev(log="ssh", event_type="ssh_auth", src=src, dst=dst, dport=22, auth_success=False,
              ts=start + timedelta(seconds=20 * i)) for i in range(n)]
    if success:
        out.append(ev(log="ssh", event_type="ssh_auth", src=src, dst=dst, dport=22, auth_success=True,
                      ts=start + timedelta(seconds=20 * n + 30)))
    return out


def test_bruteforce_and_success_detection(cfg):
    events = brute_force(success=True)
    run_detectors(events, cfg.correlation, get_catalog())
    assert all("ssh_bruteforce" in e.tags for e in events[:-1])
    assert "auth_success_after_failures" in events[-1].tags
    few = brute_force(n=3)
    run_detectors(few, cfg.correlation, get_catalog())
    assert not any(e.tags for e in few)


def test_scan_and_beacon_and_exfil_detection(cfg):
    sweep = [ev(src="192.168.56.1", dst=f"10.10.0.{i}", dport=22, conn_state="S0", duration=0.0,
                ts=T0 + timedelta(seconds=5 * i)) for i in range(3, 25)]
    beacon = [ev(src="10.10.0.20", dst="203.0.113.45", dport=443, conn_state="SF", duration=0.5,
                 ts=T0 + timedelta(seconds=120 * i + (i % 3))) for i in range(12)]
    big = ev(src="10.10.0.20", dst="198.51.100.77", dport=443, bytes_sent=400_000_000, duration=600)
    tunnel = ev(sensor="zeek", log="dns", event_type="dns_query", src="10.10.0.31", dst="198.51.100.9",
                dns_query="ab7k2m4q9z3x8c5v1n6b0w4e7r2t9y5u3i8o1p6a4s2d7f.t.example.net")
    events = sweep + beacon + [big, tunnel]
    run_detectors(events, cfg.correlation, get_catalog())
    assert all("host_sweep" in e.tags for e in sweep)
    assert all("beacon" in e.tags for e in beacon)
    assert "large_outbound" in big.tags and "dns_tunnel" in tunnel.tags


def test_irregular_traffic_is_not_a_beacon(cfg):
    import random
    rnd = random.Random(1)
    evs = [ev(src="10.10.0.40", dst="203.0.113.100", dport=443, duration=1,
              ts=T0 + timedelta(seconds=rnd.randrange(0, 20000))) for _ in range(15)]
    run_detectors(evs, cfg.correlation, get_catalog())
    assert not any("beacon" in e.tags for e in evs)


def test_temporal_and_entity_linking(cfg):
    a = ev(src="192.168.56.9", dst="10.10.0.5", tags={"ssh_bruteforce"})
    b = ev(src="192.168.56.9", dst="10.10.0.5", tags={"ssh_bruteforce"}, ts=T0 + timedelta(minutes=5))
    far = ev(src="192.168.56.9", dst="10.10.0.5", tags={"ssh_bruteforce"}, ts=T0 + timedelta(hours=3))
    other = ev(src="192.168.1.1", dst="10.10.0.99", tags={"ssh_bruteforce"}, ts=T0 + timedelta(minutes=1))
    c = cfg.correlation
    link = score_pair(a, b, _entities(a, set()), _entities(b, set()), c)
    assert link is not None and link.rule == "same-host-pair" and link.score > 0.8
    assert score_pair(a, far, _entities(a, set()), _entities(far, set()), c) is None  # outside time window
    assert score_pair(a, other, _entities(a, set()), _entities(other, set()), c) is None  # no shared entity


def test_cross_sensor_same_flow(cfg):
    z = ev(sensor="zeek", src="10.10.0.20", dst="203.0.113.45", community_id="1:x", tags={"beacon"})
    s = ev(sensor="suricata", event_type="ids_alert", src="10.10.0.20", dst="203.0.113.45", community_id="1:x",
           tags={"ids_alert", "c2_signature"}, ts=T0 + timedelta(seconds=1))
    link = score_pair(z, s, _entities(z, set()), _entities(s, set()), cfg.correlation)
    assert link.rule.startswith("same-flow") and "cross-sensor" in link.rule and link.cross_sensor == 1


def test_context_free_alert_does_not_join_through_busy_server(cfg):
    """A policy alert touching the attacked server must not merge into the attack (baseline B does)."""
    attack = [ev(src="10.10.0.20", dst="203.0.113.45", dport=443, tags={"beacon"}, ts=T0 + timedelta(minutes=2 * i))
              for i in range(10)]
    policy = ev(sensor="suricata", event_type="ids_alert", src="10.10.0.52", dst="10.10.0.20", dport=80,
                tags={"ids_alert", "policy_signature"}, ts=T0 + timedelta(minutes=7))
    res = correlate(attack + [policy], cfg.correlation)
    assert len(res.groups) == 1 and policy.event_id not in res.groups[0].event_ids
    base = baseline_rule_based(attack + [policy], cfg.correlation)
    assert any(policy.event_id in g and len(g) > 1 for g in base)


def test_infrastructure_ip_never_links_alone(cfg):
    a = ev(src="10.10.0.41", dst="10.10.0.2", tags={"dns_tunnel"})
    b = ev(src="10.10.0.42", dst="10.10.0.2", tags={"dns_tunnel"}, ts=T0 + timedelta(seconds=10))
    res = correlate([a, b], cfg.correlation)
    assert res.groups == []


def test_time_gap_splits_incidents(cfg):
    first = [ev(src="192.168.56.9", dst="10.10.0.5", tags={"ssh_bruteforce"}, ts=T0 + timedelta(minutes=i)) for i in range(5)]
    second = [ev(src="192.168.56.9", dst="10.10.0.5", tags={"ssh_bruteforce"}, ts=T0 + timedelta(hours=6, minutes=i)) for i in range(5)]
    res = correlate(first + second, cfg.correlation)
    assert len(res.groups) == 2


def test_stage_evidence_states_and_no_invention():
    members = brute_force(n=12)
    for e in members:
        e.tags.add("ssh_bruteforce")
    beacons = [ev(src="10.10.0.5", dst="203.0.113.45", tags={"beacon"}, ts=T0 + timedelta(hours=1, minutes=2 * i)) for i in range(5)]
    stages = {s.stage: s for s in reconstruct(members + beacons)}
    assert stages["credential_access"].status == "OBSERVED"
    assert stages["command_and_control"].status == "INFERRED"            # timing only -> hypothesis
    assert stages["initial_access"].status == "INFERRED"                 # implied by later behaviour of the target
    assert stages["exfiltration"].status == "NOT_OBSERVED"
    assert stages["reconnaissance"].status == "NOT_OBSERVED"


def test_attack_mapping_validated():
    cat = get_catalog()
    import pytest
    with pytest.raises(CatalogError):
        cat.validate_mapping("TA0011", "T9999")
    with pytest.raises(CatalogError):
        cat.validate_mapping("TA0006", "T1071")  # technique not under that tactic
    members = [ev(tags={"beacon"}, src="10.10.0.1", dst="203.0.113.1")]
    maps, warnings = map_incident(members, cat)
    assert [(m.technique_id, m.status) for m in maps] == [("T1071", "INFERRED")] and not warnings


def test_risk_and_confidence_are_separate_and_dedupe_repeats(cfg):
    one = [ev(sensor="suricata", event_type="ids_alert", signature_id=1, severity=2, src="1.1.1.1", dst="10.10.0.5",
              tags={"ids_alert", "bruteforce_signature"})]
    many = one * 50
    stages = reconstruct(one)
    r1, b1, _ = compute_risk(one, stages, cfg.risk, cfg.correlation)
    r50, _, _ = compute_risk(many, stages, cfg.risk, cfg.correlation)
    sev_points = [b for b in b1 if b["factor"] in ("severity", "corroboration")]
    assert all(b["points"] >= 0 for b in sev_points)
    assert abs(r1 - r50) < 5   # repeated copies don't inflate severity/corroboration
    conf, cb = compute_confidence(one, [])
    assert conf == 0.0
    assert severity_label(85, cfg.risk) == "Critical" and severity_label(10, cfg.risk) == "Informational"


def test_known_scanner_penalty(cfg):
    sweep = [ev(src="10.10.0.250", dst=f"10.10.0.{i}", tags={"host_sweep"}) for i in range(5)]
    stages = reconstruct(sweep)
    score, breakdown, adj = compute_risk(sweep, stages, cfg.risk, cfg.correlation)
    assert "known_scanner" in adj and any(b["factor"] == "known_scanner" for b in breakdown)


def test_group_dataclass():
    assert Group(["a"]).links == []
