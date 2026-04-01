#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8110}"
API_BASE="http://${API_HOST}:${API_PORT}"
STARTED_API=0
API_PID=""

cleanup() {
  if [[ "$STARTED_API" -eq 1 && -n "$API_PID" ]]; then
    kill "$API_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }
}

need_cmd curl
need_cmd python3
need_cmd uvicorn

if ! curl -fsS "$API_BASE/config" >/dev/null 2>&1; then
  echo "API not reachable on $API_BASE, starting temporary uvicorn..."
  cd "$ROOT_DIR"
  uvicorn app:app --host "$API_HOST" --port "$API_PORT" >/tmp/rbac_smoke_api.log 2>&1 &
  API_PID=$!
  STARTED_API=1
  sleep 2
fi

echo "[1/4] Python syntax check"
python3 -m py_compile "$ROOT_DIR/app.py" "$ROOT_DIR/rbac-webserver.py" "$ROOT_DIR/rbac-auditor-simple.py"

echo "[2/4] API health/config"
curl -fsS "$API_BASE/config" >/dev/null

echo "[3/4] Generate matrix + compliance"
curl -fsS -X POST "$API_BASE/generate-matrix" -H "Content-Type: application/json" >/tmp/rbac_matrix_resp.json
curl -fsS "$API_BASE/compliance-check" >/tmp/rbac_risks_resp.json

python3 - <<'PY'
import json
m = json.load(open('/tmp/rbac_matrix_resp.json'))
r = json.load(open('/tmp/rbac_risks_resp.json'))
rows = m.get('matrix', {}).get('matrix', [])
assert isinstance(rows, list) and rows, 'matrix rows empty'
assert 'high_risk_count' in r, 'missing high_risk_count'
print('matrix_rows=', len(rows), 'high_risk_count=', r.get('high_risk_count'))
PY

echo "[4/4] Frontend build"
cd "$ROOT_DIR/dashboard"
npm run build >/dev/null

echo "SMOKE TEST: OK"
