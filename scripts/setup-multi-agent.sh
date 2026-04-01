#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="$(dirname "$ROOT")"

CODE_DIR="${BASE}/rbac-coder"
ARCH_DIR="${BASE}/rbac-arch"
TEST_DIR="${BASE}/rbac-test"

sync_dir() {
  local target="$1"
  mkdir -p "$target"
  rsync -a --delete \
    --exclude '.venv' \
    --exclude 'dashboard/node_modules' \
    --exclude '__pycache__' \
    --exclude '.git' \
    "$ROOT/" "$target/"
}

sync_dir "$CODE_DIR"
sync_dir "$ARCH_DIR"
sync_dir "$TEST_DIR"

cat <<MSG
Workspaces prêts:
- $CODE_DIR
- $ARCH_DIR
- $TEST_DIR

Lance les 3 agents (3 terminaux):
  codex -C "$CODE_DIR" "Tu es l'agent CODE. Implémente les features demandées sans casser l'existant."
  codex -C "$ARCH_DIR" "Tu es l'agent AMELIORATION. Propose refacto, sécurité, perf, UX gouvernance."
  codex -C "$TEST_DIR" "Tu es l'agent TEST. Ajoute tests API/UI, smoke tests et non-régression."
MSG
