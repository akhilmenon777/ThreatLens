import json
from datetime import datetime

import pytest

from app.ingestion import suricata, zeek
from app.ingestion.service import detect_sensor
from app.normalization.schema import RecordRejected, clean_text, parse_timestamp

EVE = {"timestamp": "2026-10-20T09:00:00.123456+0530", "flow_id": 12, "event_type": "alert", "src_ip": "10.0.0.1",
       "src_port": 4444, "dest_ip": "203.0.113.5", "dest_port": 22, "proto": "TCP", "community_id": "1:abc",
       "alert": {"signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "category": "Attempted Information Leak", "severity": 2}}


def test_timestamp_normalisation():
    assert parse_timestamp("2026-10-20T09:00:00+0530") == datetime(2026, 10, 20, 3, 30)
    assert parse_timestamp("2026-10-20T03:30:00Z") == datetime(2026, 10, 20, 3, 30)
    assert parse_timestamp(1792468800.0) == datetime(2026, 10, 20, 4, 0)  # epoch seconds are UTC
    for bad in (None, "", "yesterday", True, "99999999999999"):
        with pytest.raises(RecordRejected):
            parse_timestamp(bad)


def test_suricata_alert_parsing():
    ev = suricata.parse_record(EVE, "eve.json:1", 2048, 8000)
    assert ev.event_type == "ids_alert"
    assert ev.timestamp_utc == datetime(2026, 10, 20, 3, 30, 0, 123456)
    assert (ev.source_ip, ev.destination_port, ev.transport_protocol) == ("10.0.0.1", 22, "tcp")
    assert ev.alert_signature_id == 2001219 and ev.sensor_severity == 2
    assert ev.event_id.startswith("EV-") and len(ev.event_id) == 19
    assert json.loads(ev.raw_payload)["alert"]["signature"] == EVE["alert"]["signature"]
    # deterministic ids
    assert suricata.parse_record(dict(EVE), "x", 2048, 8000).event_id == ev.event_id


def test_suricata_invalid_fields_are_warned_not_invented():
    bad = {**EVE, "src_ip": "999.1.1.1", "dest_port": 70000}
    ev = suricata.parse_record(bad, "r", 2048, 8000)
    assert ev.source_ip is None and ev.destination_port is None
    assert any("src_ip" in w for w in ev.normalization_warnings)
    assert ev.user_identity is None and ev.source_host is None
    with pytest.raises(RecordRejected):
        suricata.parse_record({"event_type": "stats"}, "r", 2048, 8000)
    with pytest.raises(RecordRejected):
        suricata.parse_record([1, 2], "r", 2048, 8000)


def test_untrusted_text_is_cleaned_and_capped():
    w = []
    out = clean_text("ab\x07c" + "x" * 50, 10, w, "ua")
    assert out == "abc" + "x" * 7 and len(w) == 2


def test_zeek_json_and_tsv():
    rec = {"_path": "ssh", "ts": 1792468800.5, "uid": "C1", "id.orig_h": "10.0.0.1", "id.orig_p": 5,
           "id.resp_h": "10.0.0.2", "id.resp_p": 22, "auth_success": False}
    ev = zeek.parse_record(rec, None, "ssh.log:1", 2048, 8000)
    assert ev.event_type == "ssh_auth" and ev.auth_success is False and ev.sensor_severity is None
    tsv = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\torig_bytes\n"
           "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tcount\n"
           "1792468800.0\tC9\t10.0.0.1\t1234\t10.0.0.9\t80\ttcp\tREJ\t-\n"
           "1792468801.0\tbroken line\n")
    rows = list(zeek.iter_records(tsv, "conn.log"))
    assert len(rows) == 2
    _, _, obj, path = rows[0]
    ev = zeek.parse_record(obj, path, "conn.log:8", 2048, 8000)
    assert ev.connection_state == "REJ" and ev.destination_port == 80 and ev.bytes_sent is None
    assert isinstance(rows[1][2], RecordRejected)


def test_sensor_detection():
    assert detect_sensor(json.dumps(EVE), "upload.json") == "suricata"
    assert detect_sensor('{"_path":"dns","ts":1}', "x.json") == "zeek"
    assert detect_sensor("", "conn.log") == "zeek"
