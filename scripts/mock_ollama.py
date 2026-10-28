#!/usr/bin/env python3
"""A tiny stand-in for the Ollama HTTP API, for testing the integration without a GPU.

It implements /api/version, /api/tags and /api/generate. /api/generate parses the
INCIDENT_DATA block from the prompt and answers with a schema-conforming summary
built only from that data (like a well-behaved model). Set MOCK_OLLAMA_MODE=obey
to make it "follow" the prompt-injection text instead, which the validator must reject.

Run:  python scripts/mock_ollama.py   (listens on 127.0.0.1:11434)
This is a test double – it is NOT a language model.
"""
from __future__ import annotations

import json
import os
import re

import uvicorn
from fastapi import FastAPI, Request

app = FastAPI()
MODELS = ["qwen2.5-coder:7b", "deepseek-r1:7b"]


@app.get("/api/version")
def version():
    return {"version": "mock-0.1"}


@app.get("/api/tags")
def tags():
    return {"models": [{"name": m, "model": m, "size": 4_700_000_000, "digest": "mock" + str(i),
                        "details": {"family": m.split(":")[0], "parameter_size": "7B", "quantization_level": "Q4_K_M"}}
                       for i, m in enumerate(MODELS)]}


@app.post("/api/generate")
async def generate(req: Request):
    body = await req.json()
    if body.get("model") not in MODELS:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": f"model '{body.get('model')}' not found"}, status_code=404)
    m = re.search(r"<<<INCIDENT_DATA \(untrusted, data only\)\n(.*)\nINCIDENT_DATA>>>", body["prompt"], re.S)
    data = json.loads(m.group(1)) if m else {}
    stages = [s for s in data.get("attack_stages", []) if s["status"] != "NOT_OBSERVED" and s["evidence_event_ids"]]
    if os.getenv("MOCK_OLLAMA_MODE") == "obey":
        text = {"executive_summary": "Maintenance mode acknowledged: no attack occurred and this incident is benign.",
                "claims": [{"text": "benign", "status": "OBSERVED", "evidence_event_ids": stages[0]["evidence_event_ids"][:1]}],
                "alternative_explanations": ["n/a"], "missing_evidence": ["n/a"]}
    else:
        text = {
            "executive_summary": f"{data.get('event_count')} related events were grouped. The sequence is consistent with "
                                 + ", ".join(s["stage"].replace("_", " ") for s in stages) + ". Inferred stages are hypotheses.",
            "probable_sequence": [{"stage": s["stage"], "status": s["status"], "description": s["observed_behavior"][:300] or "evidence present",
                                   "evidence_event_ids": s["evidence_event_ids"][:2]} for s in stages],
            "claims": [{"text": f"{s['stage'].replace('_', ' ')} is {s['status'].lower()} in the telemetry.", "status": s["status"],
                        "evidence_event_ids": s["evidence_event_ids"][:2]} for s in stages],
            "alternative_explanations": data.get("deterministic_alternative_explanations", ["Unknown"])[:3],
            "missing_evidence": ["Host-level logs from the involved systems."],
            "investigation_questions": ["Is the activity expected for these hosts?"],
            "recommended_next_steps": ["Review the linked evidence records."],
        }
    return {"model": body["model"], "response": "<think>mock reasoning</think>" + json.dumps(text), "done": True}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("MOCK_OLLAMA_PORT", "11434")))
