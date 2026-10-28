"""Minimal Ollama HTTP client (local runtime only; no cloud fallback)."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx


class OllamaUnavailable(Exception):
    pass


@dataclass
class GenerateResult:
    text: str
    model: str
    latency_ms: float
    model_version: str | None = None


def list_models(base_url: str, timeout: float = 3.0) -> list[dict]:
    try:
        r = httpx.get(f"{base_url}/api/tags", timeout=timeout)
        r.raise_for_status()
    except (httpx.HTTPError, OSError) as exc:
        raise OllamaUnavailable(f"Ollama not reachable at {base_url}: {type(exc).__name__}") from exc
    out = []
    for m in r.json().get("models", []):
        det = m.get("details") or {}
        out.append({"name": m.get("name") or m.get("model"), "size": m.get("size"),
                    "digest": (m.get("digest") or "")[:12], "family": det.get("family"),
                    "parameter_size": det.get("parameter_size"), "quantization": det.get("quantization_level")})
    return out


def server_version(base_url: str, timeout: float = 3.0) -> str | None:
    try:
        r = httpx.get(f"{base_url}/api/version", timeout=timeout)
        r.raise_for_status()
        return r.json().get("version")
    except (httpx.HTTPError, OSError, ValueError):
        return None


_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def generate(base_url: str, model: str, system: str, prompt: str, timeout: float, temperature: float) -> GenerateResult:
    body = {"model": model, "system": system, "prompt": prompt, "stream": False, "format": "json",
            "options": {"temperature": temperature, "num_ctx": 8192}}
    t0 = time.perf_counter()
    try:
        r = httpx.post(f"{base_url}/api/generate", json=body, timeout=timeout)
    except httpx.TimeoutException as exc:
        raise OllamaUnavailable(f"Ollama timed out after {timeout:.0f}s") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise OllamaUnavailable(f"Ollama not reachable at {base_url}: {type(exc).__name__}") from exc
    if r.status_code == 404:
        raise OllamaUnavailable(f"Model '{model}' is not installed (run: ollama pull {model})")
    if r.status_code >= 400:
        raise OllamaUnavailable(f"Ollama error {r.status_code}: {r.text[:200]}")
    data = r.json()
    text = _THINK.sub("", data.get("response", "")).strip()
    return GenerateResult(text=text, model=data.get("model", model),
                          latency_ms=round((time.perf_counter() - t0) * 1000, 1))
