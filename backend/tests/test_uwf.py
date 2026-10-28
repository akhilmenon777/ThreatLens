"""UWF-ZeekData CSV import, ground-truth labels, analytics and label-based evaluation."""
import io
import time

HEADER = ("community_id,conn_state,duration,history,src_ip_zeek,src_port_zeek,dest_ip_zeek,dest_port_zeek,local_orig,"
          "local_resp,missed_bytes,orig_bytes,orig_ip_bytes,orig_pkts,proto,resp_bytes,resp_ip_bytes,resp_pkts,service,"
          "ts,uid,datetime,label_tactic,label_technique,label_binary,label_cve")


def _row(i, src, dst, dport, ts, tactic, technique, state="SF", binary="True"):
    return (f"1:cid{i}=,{state},0.0063,ShAFaf,{src},{40000 + i},{dst},{dport},false,false,0,0,864,16,tcp,0,656,12,,"
            f"{ts:.6f},C{i:08d},2024-03-01T10:00:00Z,{tactic},{technique},{binary},none")


def _csv():
    t0 = 1.7092889e9
    rows = [HEADER]
    # brute force: 40 connections to an admin console within ~7 min
    rows += [_row(i, "143.88.3.11", "143.88.4.13", 4848, t0 + i * 10, "Credential Access", "T1110") for i in range(40)]
    # port scan: 20 ports on one host within a minute
    rows += [_row(100 + p, "143.88.10.12", "143.88.11.4", 1000 + p, t0 + 2000 + p, "Reconnaissance", "T1595", "REJ")
             for p in range(20)]
    # benign DNS
    rows += [_row(200 + i, "143.88.0.6", "8.8.8.8", 53, t0 + 50 + i * i * 37 + (i % 3) * 11, "none", "none", "S0", "False")
             for i in range(15)]
    # the same connection labelled with a second tactic (dataset marks it "Duplicate")
    rows.append(_row(0, "143.88.3.11", "143.88.4.13", 4848, t0, "Persistence", "Duplicate", binary="Duplicate"))
    rows.append("not,a,valid,row")
    return "\n".join(rows) + "\n"


def test_uwf_upload_labels_and_analytics(client):
    prev = next((d for d in client.get("/api/datasets").json() if d["is_active"]), None)
    ds = client.post("/api/datasets", data={"name": "UWF unit test"}).json()
    r = client.post("/api/ingest", files={"file": ("uwf_part.csv", io.BytesIO(_csv().encode()), "text/csv")},
                    data={"sensor": "auto", "run_correlation_after": "true"})
    assert r.status_code == 200, r.text
    job = r.json()["job"]
    assert job["file_format"] == "uwf-zeek-csv" and job["sensor"] == "zeek"
    assert job["accepted"] == 75 and job["duplicates"] == 1 and job["rejected"] == 1
    assert r.json()["correlation"]["n_incidents"] >= 1

    s = client.get("/api/settings").json()
    assert "143.88.0.0/16" in s["correlation"]["internal_networks"]

    ds_out = next(d for d in client.get("/api/datasets").json() if d["id"] == ds["id"])
    assert ds_out["has_labels"]

    a = client.get("/api/analytics").json()
    gt = a["ground_truth"]
    assert gt["available"] and gt["malicious"] == 60 and gt["benign"] == 15
    tactics = {t["tactic"]: t for t in gt["tactics"]}
    assert tactics["Persistence"]["events"] == 1 and tactics["Credential Access"]["events"] == 40
    assert tactics["Credential Access"]["tagged"] >= 20
    assert a["totals"]["events"] == 75 and a["timeline"]

    # label filter + ground truth on the event (never inside the raw payload)
    ev = client.get("/api/events?label=Credential Access&page_size=5").json()
    assert ev["total"] == 40
    one = client.get(f"/api/events/{ev['items'][0]['event_id']}").json()
    assert "Credential Access" in one["ground_truth"]["tactics"] and "label_tactic" not in one["raw_payload"]
    assert set(client.get("/api/events/labels").json()) >= {"Credential Access", "Reconnaissance", "Persistence"}

    # evaluation scores against the per-event labels
    run = client.post("/api/evaluation/run", json={"include_llm": False}).json()
    for _ in range(60):
        res = client.get(f"/api/evaluation/runs/{run['id']}").json()
        if res["status"] != "running":
            break
        time.sleep(0.3)
    assert res["status"] == "completed", res["message"]
    ls = res["results"]["label_scores"]
    assert ls["labelled_malicious"] == 60
    prop = res["results"]["methods"]["proposed_evidence_aware"]
    assert prop["detection"]["precision"] == 1.0 and prop["detection"]["tp"] >= 40
    md = client.get(f"/api/evaluation/runs/{run['id']}/export?format=md").text
    assert "Detection against dataset labels" in md

    client.delete(f"/api/datasets/{ds['id']}")
    if prev:
        client.post(f"/api/datasets/{prev['id']}/activate")


def test_uwf_bundled_info(client):
    info = client.get("/api/uwf").json()
    assert {p["id"] for p in info["parts"]} == {"2024", "2025", "ait"}
    assert all(p["files"] for p in info["parts"])
    assert client.get("/api/tasks/doesnotexist").status_code == 404
