"""FastAPI application entry point.

Run (from backend/):  uvicorn app.main:app --reload --port 8000
OpenAPI docs:         http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import PROJECT_ROOT, get_env
from app.core.db import init_db

log = logging.getLogger("ntdcp")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    _fail_interrupted_runs()
    yield


def _fail_interrupted_runs() -> None:
    """Evaluation runs are background jobs; one still 'running' at start-up was interrupted."""
    from sqlalchemy import update

    from app.core.db import session_scope
    from app.models import EvaluationRun
    with session_scope() as s:
        s.execute(update(EvaluationRun).where(EvaluationRun.status == "running")
                  .values(status="failed", message="Interrupted: the backend was restarted while this run was in progress."))


app = FastAPI(title="Network Threat Detection & Attack Correlation Platform",
              version=get_env().app_version,
              description="Passive blue-team analysis layer over Suricata and Zeek telemetry. "
                          "Incidents are hypotheses for analyst review, not proof of attack.",
              lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=get_env().cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/incidents/") and request.url.path.endswith("/report"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg")} for e in exc.errors()[:20]]
    return JSONResponse(status_code=422, content={"detail": "Validation failed", "errors": errors})


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):  # pragma: no cover - last resort
    log.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error (see backend log)"})


app.include_router(router)

# Serve the built frontend (frontend/dist) when present, so a single process can host the app.
DIST = PROJECT_ROOT / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        candidate = (DIST / path).resolve()
        if path and candidate.is_file() and DIST.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(DIST / "index.html")
