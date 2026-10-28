#!/usr/bin/env python3
"""Browser end-to-end smoke test (Playwright + Chromium) against a running app.

Prereqs: backend running on :8000 serving the built frontend (frontend/dist),
`pip install playwright && python -m playwright install chromium`.
Run:  python scripts/e2e_smoke.py [base_url]
"""
import json
import sys
import time
import urllib.request

from playwright.sync_api import expect, sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
steps = []


def step(name):
    steps.append(name)
    print(f"✓ {name}")


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(f"{BASE}/ingestion")
    page.get_by_role("button", name="Load synthetic demo").first.click()
    expect(page.get_by_text("Demo loaded:")).to_be_visible(timeout=60000)
    step("load demo data via UI (ingest + correlate)")

    page.goto(f"{BASE}/")
    expect(page.get_by_text("raw events").first).to_be_visible()
    expect(page.get_by_text("Activity over time")).to_be_visible()
    step("overview shows computed totals and charts")

    page.goto(f"{BASE}/incidents")
    first = page.locator("tbody tr").first
    expect(first).to_be_visible()
    title = first.locator("td").first.inner_text().split("\n")[0]
    first.click()
    expect(page.get_by_text("Attack chain")).to_be_visible()
    expect(page.get_by_text("Hypothesis, not proof of attack.")).to_be_visible()
    step(f"open incident: {title[:60]}")

    page.get_by_role("button", name="Show").first.click()
    expect(page.locator("#timeline tbody tr").first).to_be_visible()
    page.locator("#timeline tbody tr button").first.click()
    expect(page.get_by_text("Original source payload")).to_be_visible()
    page.keyboard.press("Escape")
    step("timeline + evidence drawer with raw payload")

    page.get_by_role("button", name="Template summary").click()
    expect(page.get_by_text("Deterministic fallback summary (no LLM)")).to_be_visible(timeout=20000)
    expect(page.get_by_text("Executive summary")).to_be_visible()
    step("deterministic summary generated and labelled")

    page.get_by_label("Status").select_option("in_progress")
    expect(page.get_by_text("Status set to In progress")).to_be_visible()
    page.get_by_label("Add note").fill("E2E: checked web server auth logs")
    page.get_by_role("button", name="Save note").click()
    expect(page.get_by_text("E2E: checked web server auth logs")).to_be_visible()
    inc_id = page.url.rstrip("/").split("/")[-1]
    page.reload()
    expect(page.get_by_text("E2E: checked web server auth logs")).to_be_visible()
    expect(page.get_by_label("Status")).to_have_value("in_progress")
    step("status change + note persist across reload")

    with urllib.request.urlopen(f"{BASE}/api/incidents/{inc_id}/report?format=html") as r:
        html = r.read().decode()
    assert "Hypothesis, not proof of attack" in html and "E2E: checked" in html
    step("HTML report export contains notes and disclaimer")

    page.goto(f"{BASE}/events?assigned=no&tagged=true")
    expect(page.locator("tbody tr").first).to_be_visible()
    step("raw events: unassigned alert-bearing events listed")

    page.goto(f"{BASE}/attack")
    page.get_by_text("T1110.001").click()
    expect(page.get_by_text("Associated incidents")).to_be_visible()
    step("ATT&CK explorer technique drill-down")

    page.goto(f"{BASE}/evaluation")
    page.get_by_role("button", name="Run evaluation").click()
    expect(page.get_by_text("Correlation approaches compared")).to_be_visible(timeout=60000)
    step("evaluation run executed and rendered")

    page.goto(f"{BASE}/settings")
    page.get_by_role("button", name="Test connection & discover models").click()
    expect(page.locator("text=/Ollama|Connected/").first).to_be_visible()
    step("settings: Ollama connection check")

    browser.close()
    if errors:
        print("Page errors:", errors)
        sys.exit(1)
print(f"\nE2E smoke test passed: {len(steps)} steps")
