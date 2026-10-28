"""AIT-ADS (Wazuh / Suricata-via-Wazuh / AMiner) parsing, labelling and host-alert detection."""
import json
from datetime import datetime, timedelta

import pytest

from app.ingestion import ait
from app.ingestion.service import detect_sensor, ingest_text
from app.models import EventLabel

EVE = {"agent": {"ip": "10.35.32.1", "name": "wazuh-client", "id": "29"}, "manager": {"name": "wazuh.manager"},
       "data": {"src_ip": "192.168.128.4", "src_port": "56852", "event_type": "alert", "dest_ip": "91.189.95.85",
                "dest_port": "80", "proto": "TCP", "flow_id": "124443513033886.000000",
                "alert": {"severity": "3", "signature_id": "2013504", "signature": "ET SCAN Possible Nmap User-Agent Observed",
                          "category": "Web Application Attack"},
                "timestamp": "2022-01-15T03:45:39.681006+0000"},
       "rule": {"level": 3, "description": "Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed",
                "groups": ["ids", "suricata"], "id": "86601"},
       "@timestamp": "2022-01-15T03:45:39.681006Z", "location": "/var/log/suricata/eve.json", "id": "1.1"}
FAST = {"predecoder": {"timestamp": "01/21/2022-00:14:21.351958"}, "agent": {"ip": "172.19.128.1", "id": "22"},
        "data": {"srcip": "192.168.230.4", "dstip": "91.189.95.85:80", "id": "1:2013504:6"},
        "rule": {"level": 6, "description": "IDS event.", "groups": ["ids"], "id": "20101"},
        "full_log": "01/21/2022-00:14:21.351958  [**] [1:2013504:6] ET POLICY GNU/Linux APT User-Agent Outbound "
                    "[**] [Classification: Not Suspicious Traffic] [Priority: 3] {TCP} 192.168.230.4:44510 -> 91.189.95.85:80",
        "@timestamp": "2022-01-21T00:14:21.351958Z", "location": "/var/log/suricata/fast.log", "id": "1.2"}


def web400(i: int, src="172.19.131.174", t0=datetime(2022, 1, 24, 3, 57)):
    ts = (t0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"agent": {"ip": "10.143.2.4", "id": "10"}, "data": {"protocol": "GET", "srcip": src, "id": "404",
                                                                "url": f"/admin{i}"},
            "rule": {"level": 5, "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"],
                     "id": "31101"},
            "full_log": f"intranet:80 {src} - - [x] \"GET /admin{i} HTTP/1.1\" 404 1",
            "@timestamp": ts, "location": "/var/log/apache2/intranet-access.log", "id": f"2.{i}"}


AMINER = {"AnalysisComponent": {"AnalysisComponentType": "EntropyDetector",
                                "AnalysisComponentName": "AMiner: High entropy in DNS domain.",
                                "Message": "Value entropy anomaly detected"},
          "LogData": {"RawLogData": ["Jan 21 00:00:09 dnsmasq[3326]: query[A] x7f3k.q9z.example.info from 192.168.230.4"],
                      "Timestamps": [1642723209], "LogResources": ["/var/log/dnsmasq.log"]},
          "AMiner": {"ID": "192.168.231.254"}}


@pytest.fixture
def session(client):
    """A session for direct service calls; datasets it creates are removed afterwards and the
    previously active dataset is re-activated, so other tests are unaffected."""
    from sqlalchemy.orm import Session

    from app.core.db import get_engine
    from app.models import Dataset
    s = Session(bind=get_engine(), autoflush=False, expire_on_commit=False)
    before = {d.id: d.is_active for d in s.query(Dataset)}
    try:
        yield s
    finally:
        s.rollback()
        for d in s.query(Dataset).all():
            if d.id not in before:
                s.delete(d)
            else:
                d.is_active = before[d.id]
        s.commit()
        s.close()


@pytest.fixture
def settings(cfg):
    return cfg


def test_detect_and_parse_kinds():
    assert ait.looks_like_ait(json.dumps(EVE)) == "wazuh"
    assert ait.looks_like_ait(json.dumps(AMINER)) == "aminer"
    assert detect_sensor(json.dumps(AMINER), "x.json") == "ait"

    ev = ait.parse_record(EVE, "wazuh", "f:1", 2000, 8000)
    assert (ev.source_sensor, ev.event_type, ev.source_ip, ev.destination_port) == ("suricata", "ids_alert", "192.168.128.4", 80)
    assert ev.alert_signature.startswith("ET SCAN")

    fast = ait.parse_record(FAST, "wazuh", "f:2", 2000, 8000)
    assert (fast.source_sensor, fast.source_log, fast.event_type) == ("suricata", "fast", "ids_alert")
    assert (fast.source_ip, fast.source_port, fast.destination_ip, fast.destination_port) == ("192.168.230.4", 44510, "91.189.95.85", 80)
    assert fast.alert_signature_id == 2013504 and fast.sensor_severity == 3

    host = ait.parse_record(web400(0), "wazuh", "f:3", 2000, 8000)
    assert (host.source_sensor, host.event_type, host.source_ip, host.destination_ip) == ("wazuh", "host_alert", "172.19.131.174", "10.143.2.4")
    assert host.http_uri == "/admin0" and host.sensor_severity == 3

    am = ait.parse_record(AMINER, "aminer", "f:4", 2000, 8000)
    assert (am.source_sensor, am.event_type, am.source_ip, am.destination_ip) == ("aminer", "anomaly_alert", "192.168.230.4", "192.168.231.254")
    assert am.dns_query == "x7f3k.q9z.example.info"


def test_wazuh_severity_scale():
    assert [ait.wazuh_severity(x) for x in (3, 7, 10, 12, 15, "bad")] == [3, 2, 2, 1, 1, None]


def test_phase_labels_from_windows_and_sidecar(session, settings):
    from app.services.datasets import create_dataset
    ds = create_dataset(session, "ait test")
    lines = [json.dumps(web400(i)) for i in range(3)]
    # sidecar labels: only line 2 is attack (dirb)
    job = ingest_text(session, ds, "\n".join(lines), "russellmitchell_wazuh.json", "ait", settings, line_phases={2: "dirb"})
    assert job.accepted == 3 and job.sensor == "wazuh"
    labs = {r.malicious: r for r in session.query(EventLabel).filter_by(dataset_id=ds.id)}
    assert labs[True].tactics == ["Reconnaissance"] and labs[True].techniques == ["T1595.003"]
    assert session.query(EventLabel).filter_by(dataset_id=ds.id, malicious=False).count() == 2
    assert "ait" in ds.labels["sources"]


def test_web_error_burst_and_anomaly_only_groups(session, settings):
    from app.services.datasets import create_dataset
    from app.services.pipeline import run_correlation
    ds = create_dataset(session, "ait burst")
    text = "\n".join(json.dumps(web400(i)) for i in range(40))
    ingest_text(session, ds, text, "x_wazuh.json", "ait", settings)
    # AMiner-only activity must not open an incident on its own
    am = [dict(AMINER, LogData=dict(AMINER["LogData"], Timestamps=[1642723209 + i])) for i in range(5)]
    ingest_text(session, ds, "\n".join(json.dumps(a) for a in am), "y_aminer.json", "ait", settings)
    run = run_correlation(session, ds, settings)
    tags = run.params["detector_tag_counts"]
    assert tags.get("web_error_burst") == 40 and tags.get("dns_anomaly") == 5
    assert run.n_incidents == 1
    from app.models import Incident
    inc = session.query(Incident).filter_by(dataset_id=ds.id).one()
    assert any(m.technique_id == "T1595.003" for m in inc.mappings)
