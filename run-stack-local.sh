#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-8110}"
DASH_PORT="${DASH_PORT:-8111}"
MODE="${1:-dev}"

if [[ "$MODE" == "--prod" || "$MODE" == "prod" ]]; then
  MODE="prod"
else
  MODE="dev"
fi

UVICORN_BIN="${UVICORN_BIN:-$ROOT_DIR/.venv/bin/uvicorn}"
if [[ ! -x "$UVICORN_BIN" ]]; then
  UVICORN_BIN="$(command -v uvicorn || true)"
fi
if [[ -z "${UVICORN_BIN:-}" || ! -x "$UVICORN_BIN" ]]; then
  echo "uvicorn not found. Install into .venv or PATH." >&2
  exit 1
fi

cd "$ROOT_DIR/dashboard"
if [[ ! -d node_modules ]]; then
  npm install
fi

if [[ "$MODE" == "prod" ]]; then
  npm run build
fi

# Stop old listeners on target ports.
for p in "$API_PORT" "$DASH_PORT"; do
  pids="$(ss -ltnp | awk -v port=":${p}" '$4 ~ port {print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  if [[ -n "$pids" ]]; then
    kill $pids || true
  fi
done

cd "$ROOT_DIR"

cleanup() {
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" >/dev/null 2>&1 || true
  [[ -n "${WEB_PID:-}" ]] && kill "$WEB_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"$UVICORN_BIN" app:app --host "$API_HOST" --port "$API_PORT" --reload &
API_PID=$!

if [[ "$MODE" == "prod" ]]; then
  API_BASE="http://127.0.0.1:${API_PORT}" DASH_PORT="$DASH_PORT" DIST_DIR="$ROOT_DIR/dashboard/dist" node "$ROOT_DIR/serve-dashboard.mjs" &
  WEB_PID=$!
else
  cd "$ROOT_DIR/dashboard"
  npm run dev -- --host 0.0.0.0 --port "$DASH_PORT" &
  WEB_PID=$!
fi

echo "API:       http://127.0.0.1:${API_PORT}"
echo "Dashboard: http://127.0.0.1:${DASH_PORT}"
echo "Mode:      $MODE"
wait "$API_PID" "$WEB_PID"
