#!/usr/bin/env bash
codex -C "$(cd "$(dirname "$0")/../../rbac-test" && pwd)" "Tu es l'agent TEST. Ajoute tests API/UI, smoke tests et non-régression."
