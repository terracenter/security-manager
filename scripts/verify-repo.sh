#!/usr/bin/env bash
# verify-repo.sh — Validacion obligatoria de identidad del repo
# Debe ejecutarse ANTES de cualquier push, merge, deploy, o cambio de remote.
# Exit code 0 = repo verificado. No-0 = falla, abortar.

set -euo pipefail

REPO_PATH="${1:-$(git rev-parse --show-toplevel 2>/dev/null)}"
if [[ -z "$REPO_PATH" ]] || ! git -C "$REPO_PATH" rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: no es un repo git: $REPO_PATH" >&2
    exit 1
fi

cd "$REPO_PATH"

# 1. Validar remote origin
ORIGIN_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ -z "$ORIGIN_URL" ]]; then
    echo "ERROR: remote 'origin' no configurado" >&2
    exit 1
fi

# 2. Validar que el remote es el repo esperado
EXPECTED_REMOTE="git@github.com:terracenter/security-manager.git"
if [[ "$ORIGIN_URL" != "$EXPECTED_REMOTE" ]]; then
    echo "ERROR: remote origin no coincide con el repo esperado" >&2
    echo "  Actual:   $ORIGIN_URL" >&2
    echo "  Esperado: $EXPECTED_REMOTE" >&2
    exit 1
fi

# 3. Validar que el repo existe en GitHub y es accesible
if ! gh repo view terracenter/security-manager --json name,owner,isPrivate,defaultBranchRef >/dev/null 2>&1; then
    echo "ERROR: repo terracenter/security-manager no accesible via gh CLI" >&2
    exit 1
fi

# 4. Validar que la rama por defecto es main
DEFAULT_BRANCH=$(gh repo view terracenter/security-manager --json defaultBranchRef --jq '.defaultBranchRef.name' 2>/dev/null)
if [[ "$DEFAULT_BRANCH" != "main" ]]; then
    echo "ERROR: rama por defecto no es 'main' (es: $DEFAULT_BRANCH)" >&2
    exit 1
fi

# 5. Validar que no hay commits pendientes de autoría incorrecta
if git log --all --format="%an <%ae>" | grep -qE "Claude@|noreply@anthropic|noreply@openai|noreply@nousresearch"; then
    echo "ERROR: hay commits con autoría de IA en el historial" >&2
    exit 1
fi

echo "OK: repo verificado como terracenter/security-manager (main)"
exit 0
