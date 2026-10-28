#!/usr/bin/env bash
# Start backend (port 8000) and frontend dev server (port 5173) together.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
python -m uvicorn app.main:app --reload --port 8000 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT
cd "$ROOT/frontend"
npm run dev
