#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-8110}"
DASH_PORT="${DASH_PORT:-8111}"
MODE="dev"

if [[ "${1:-}" == "--prod" ]]; then
  MODE="prod"
fi

UVICORN_BIN="uvicorn"
if ! command -v "$UVICORN_BIN" >/dev/null 2>&1; then
  if [[ -x "$ROOT_DIR/.venv/bin/uvicorn" ]]; then
    UVICORN_BIN="$ROOT_DIR/.venv/bin/uvicorn"
  else
    echo "uvicorn not found. Install fastapi+uvicorn first (or create $ROOT_DIR/.venv)." >&2
    exit 1
  fi
fi

cd "$ROOT_DIR"

stop_port() {
  local port="$1"
  local pids
  pids="$(ss -ltnp | awk -v port=":${port}" '$4 ~ port {print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  if [[ -n "${pids}" ]]; then
    echo "Stopping existing process(es) on :${port} -> ${pids}"
    kill ${pids} >/dev/null 2>&1 || true
    sleep 1
  fi
}

cleanup() {
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" >/dev/null 2>&1 || true
  [[ -n "${WEB_PID:-}" ]] && kill "$WEB_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

stop_port "$API_PORT"
stop_port "$DASH_PORT"

echo "Starting RBAC API on http://${API_HOST}:${API_PORT}"
"$UVICORN_BIN" app:app --host "$API_HOST" --port "$API_PORT" --reload &
API_PID=$!

cd "$ROOT_DIR/dashboard"
if [[ ! -d node_modules ]]; then
  echo "Installing dashboard dependencies..."
  npm install
fi

if [[ "$MODE" == "prod" ]]; then
  echo "Building dashboard (production)..."
  npm run build
  echo "Starting Node dashboard gateway on http://0.0.0.0:${DASH_PORT}"
  DASH_SERVER="$ROOT_DIR/serve-dashboard.mjs"
  if [[ -x "$ROOT_DIR/serve-dashboard-local.mjs" ]]; then
    DASH_SERVER="$ROOT_DIR/serve-dashboard-local.mjs"
  fi
  API_BASE="http://127.0.0.1:${API_PORT}" DASH_PORT="$DASH_PORT" DIST_DIR="$ROOT_DIR/dashboard/dist" node "$DASH_SERVER" &
  WEB_PID=$!
else
  echo "Starting dashboard dev server on http://0.0.0.0:${DASH_PORT}"
  npm run dev -- --port "$DASH_PORT" &
  WEB_PID=$!
fi

echo

echo "API:       http://127.0.0.1:${API_PORT}"
echo "Dashboard: http://127.0.0.1:${DASH_PORT}"
echo "Mode:      $MODE"
echo "Press Ctrl+C to stop both"

wait "$API_PID" "$WEB_PID"
