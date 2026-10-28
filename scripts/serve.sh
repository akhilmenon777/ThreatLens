#!/usr/bin/env bash
# Build the frontend once and serve everything from the backend on http://127.0.0.1:8000
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$ROOT/frontend" && npm run build)
cd "$ROOT/backend" && exec python -m uvicorn app.main:app --port 8000
