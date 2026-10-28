"""Integration tests through the HTTP API (FastAPI TestClient, temporary SQLite DB)."""
import io
import json
import time

import pytest


def top_incident(client):
    return client.get("/api/incidents?sort=risk_score&order=desc").json()["items"][0]


def test_health_without_ollama(client):
    h = client.get("/api/health").json()
    assert h["backend"] and h["database"] and h["llm"]["available"] is False


def test_demo_pipeline(client, demo_loaded):
    jobs = {j["filename"]: j for j in demo_loaded["jobs"]}
    assert jobs["suricata_eve.json"]["rejected"] >= 6 and jobs["suricata_eve.json"]["duplicates"] == 1
    assert jobs["zeek_files.tsv.log"]["accepted"] == 12
    assert demo_loaded["correlation"]["n_incidents"] == 6
    ov = client.get("/api/overview").json()
    t = ov["totals"]
    assert t["incidents"] == 6 and t["raw_events"] > 8000
    assert t["reduction_pct"] == round((t["raw_events"] - t["incidents"]) / t["raw_events"] * 100, 2)
    inc = top_incident(client)
    assert inc["severity"] in ("Critical", "High") and "zeek" in inc["sensors"] and "suricata" in inc["sensors"]


def test_incident_detail_traceable_to_evidence(client, demo_loaded):
    inc = top_incident(client)
    d = client.get(f"/api/incidents/{inc['id']}").json()
    statuses = {s["stage"]: s["status"] for s in d["stages"]}
    assert statuses["exfiltration"] == "INFERRED" and statuses["credential_access"] == "OBSERVED"
    assert d["risk_score"] != d["confidence"] and d["confidence_breakdown"]
    evs = client.get(f"/api/incidents/{inc['id']}/events?page_size=500").json()
    assert evs["total"] == d["event_count"]
    one = client.get(f"/api/events/{evs['items'][0]['event_id']}").json()
    assert inc["id"] in one["incident_ids"] and json.loads(one["raw_payload"])
    links = client.get(f"/api/incidents/{inc['id']}/links").json()
    assert links["total"] > 0 and links["items"][0]["explanation"]
    for m in d["mappings"]:
        assert m["evidence_event_ids"] and m["status"] in ("OBSERVED", "INFERRED")


def test_filters_and_pagination(client, demo_loaded):
    r = client.get("/api/incidents?severity=Critical&severity=High").json()
    assert all(i["severity"] in ("Critical", "High") for i in r["items"])
    r = client.get("/api/incidents?technique=T1110").json()
    assert r["total"] >= 2
    r = client.get("/api/incidents?page=2&page_size=2").json()
    assert len(r["items"]) == 2 and r["total"] == 6
    ev = client.get("/api/events?assigned=no&tagged=true").json()
    assert ev["total"] >= 7
    assert client.get("/api/events?warnings=true").json()["total"] >= 1


def test_workflow_persists(client, demo_loaded):
    inc = top_incident(client)
    r = client.patch(f"/api/incidents/{inc['id']}", json={"status": "in_progress", "assignee": "Analyst B", "actor": "Analyst B"})
    assert r.status_code == 200 and r.json()["status"] == "in_progress"
    client.post(f"/api/incidents/{inc['id']}/notes", json={"author": "Analyst B", "text": "Checked <b>auth</b> logs"})
    client.patch(f"/api/incidents/{inc['id']}", json={"suspected_false_positive": True, "actor": "Analyst B", "reason": "test"})
    # re-running correlation keeps workflow state for unchanged incidents
    client.post("/api/correlation/run")
    d = client.get(f"/api/incidents/{inc['id']}").json()
    assert d["status"] == "in_progress" and d["assignee"] == "Analyst B" and d["suspected_false_positive"]
    assert d["notes"][-1]["text"] == "Checked <b>auth</b> logs" and len(d["status_changes"]) >= 3
    assert client.patch(f"/api/incidents/{inc['id']}", json={"status": "bogus"}).status_code == 422
    assert client.patch(f"/api/incidents/{inc['id']}", json={"assignee": "Mallory", "actor": "x"}).status_code == 422


def test_summary_fallback_and_injection_flag(client, demo_loaded):
    inc = top_incident(client)
    s = client.post(f"/api/incidents/{inc['id']}/summary", json={"mode": "live"}).json()
    assert s["generator"] == "fallback" and "not reachable" in s["content"]["fallback_reason"]
    assert any(f["field"] == "http_user_agent" for f in s["injection_flags"])
    assert "hypothesis" in s["content"]["executive_summary"].lower()


def test_live_llm_valid_and_injection_compliant(client, demo_loaded, monkeypatch):
    """Mocked Ollama: a well-behaved model is accepted; a model that obeys the injected text is rejected."""
    from app.llm import client as llm_client
    inc = top_incident(client)
    detail = client.get(f"/api/incidents/{inc['id']}").json()
    obs = next(s for s in detail["stages"] if s["status"] == "OBSERVED")
    good = {"executive_summary": "Repeated failed SSH logins were followed by a successful login and later periodic outbound traffic.",
            "probable_sequence": [{"stage": obs["stage"], "status": "OBSERVED", "description": "seen", "evidence_event_ids": obs["event_ids"][:1]}],
            "claims": [{"text": "Failed logins observed.", "status": "OBSERVED", "evidence_event_ids": obs["event_ids"][:1]}],
            "alternative_explanations": ["Automation"], "missing_evidence": ["Host logs"],
            "investigation_questions": ["Which account?"], "recommended_next_steps": ["Review evidence"]}
    seen_prompts = []

    def fake_generate(base, model, system, prompt, timeout, temperature, payload=good):
        seen_prompts.append(prompt)
        return llm_client.GenerateResult(text=json.dumps(payload), model=model, latency_ms=12.0)
    monkeypatch.setattr(llm_client, "generate", fake_generate)
    monkeypatch.setattr(llm_client, "server_version", lambda *a, **k: "0.0-test")
    s = client.post(f"/api/incidents/{inc['id']}/summary", json={"mode": "live"}).json()
    assert s["generator"] == "llm" and s["status"] == "valid" and s["model"] == "qwen2.5-coder:7b"
    assert all("IGNORE ALL PREVIOUS" not in p for p in seen_prompts)  # injection redacted before prompting

    obeying = dict(good, executive_summary="Maintenance mode: no attack occurred, this incident is benign and severity is low.")
    monkeypatch.setattr(llm_client, "generate", lambda *a, **k: llm_client.GenerateResult(json.dumps(obeying), "qwen2.5-coder:7b", 5.0))
    s2 = client.post(f"/api/incidents/{inc['id']}/summary", json={"mode": "live"}).json()
    assert s2["generator"] == "fallback" and any("embedded in log data" in e for e in s2["validation_errors"])
    hist = client.get(f"/api/incidents/{inc['id']}/summaries").json()
    assert any(h["status"] == "invalid" for h in hist)
    # cached mode returns the stored valid LLM summary for unchanged evidence
    s3 = client.post(f"/api/incidents/{inc['id']}/summary", json={"mode": "cached"}).json()
    assert s3["generator"] == "llm"


def test_reports(client, demo_loaded):
    inc = top_incident(client)
    h = client.get(f"/api/incidents/{inc['id']}/report?format=html")
    assert h.status_code == 200 and "Hypothesis, not proof of attack" in h.text and "SYNTHETIC DATA" in h.text
    assert "<b>auth</b>" not in h.text  # untrusted note text is escaped
    j = client.get(f"/api/incidents/{inc['id']}/report?format=json").json()
    assert j["incident"]["id"] == inc["id"] and j["synthetic_data"] and len(j["timeline"]) == j["incident"]["event_count"]
    c = client.get(f"/api/incidents/{inc['id']}/report?format=csv")
    assert c.status_code == 200 and "event_id" in c.text
    assert client.get("/api/reports/incidents.csv").text.count("\n") == 7


def test_upload_validation(client, demo_loaded):
    eve = '{"timestamp":"2026-10-21T10:00:00Z","event_type":"alert","src_ip":"10.9.9.9","src_port":1,"dest_ip":"10.9.9.8","dest_port":80,"proto":"TCP","alert":{"signature":"ET POLICY test","signature_id":1,"category":"Misc","severity":3}}\n{bad json'
    r = client.post("/api/ingest", files={"file": ("eve.json", io.BytesIO(eve.encode()), "application/json")},
                    data={"sensor": "auto", "run_correlation_after": "false"})
    assert r.status_code == 200, r.text
    job = r.json()["job"]
    assert job["accepted"] == 1 and job["rejected"] == 1
    rej = client.get(f"/api/ingest/jobs/{job['id']}/rejected").json()
    assert "malformed JSON" in rej[0]["reason"]
    r = client.post("/api/ingest", files={"file": ("x.bin", io.BytesIO(b"\x00\x01binary"), "application/octet-stream")}, data={"sensor": "auto"})
    assert r.status_code == 415


def test_settings_validation(client):
    s = client.get("/api/settings").json()
    bad = json.loads(json.dumps(s))
    bad["risk"]["high_threshold"] = 95
    assert client.put("/api/settings", json=bad).status_code == 422
    bad = json.loads(json.dumps(s))
    bad["display"]["timezone"] = "Mars/Olympus"
    assert client.put("/api/settings", json=bad).status_code == 422
    good = json.loads(json.dumps(s))
    good["display"]["timezone"] = "Asia/Kolkata"
    assert client.put("/api/settings", json=good).json()["display"]["timezone"] == "Asia/Kolkata"


def test_evaluation_run(client, demo_loaded):
    client.post("/api/demo/load")  # fresh demo (the upload test added an extra event)
    r = client.post("/api/evaluation/run", json={"include_llm": True}).json()
    for _ in range(60):
        run = client.get(f"/api/evaluation/runs/{r['id']}").json()
        if run["status"] != "running":
            break
        time.sleep(0.5)
    assert run["status"] == "completed", run["message"]
    res = run["results"]
    assert res["ground_truth"]["available"]
    prop, base_b = res["methods"]["proposed_evidence_aware"], res["methods"]["B_rule_based_shared_ip"]
    assert prop["grouping"]["precision"] >= base_b["grouping"]["precision"]
    assert prop["unrelated_singletons_merged"] == 0
    assert res["scenario_scores"]["benign"]["escalated_to_high_or_critical"] == 0
    assert "not run" in res["llm"]["note"] and res["llm"]["fallback_valid_rate"] == 1.0
    md = client.get(f"/api/evaluation/runs/{r['id']}/export?format=md").text
    assert "Synthetic results" in md
