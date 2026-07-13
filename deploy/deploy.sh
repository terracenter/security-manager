#!/usr/bin/env bash
set -e

BINARY="security-manager-ng"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REMOTE="${1}"
if [[ -z "${REMOTE}" ]]; then
    printf "Host remoto destino: "
    read -r REMOTE
fi
if [[ -z "${REMOTE}" ]]; then
    echo "ERROR: se requiere host destino" >&2
    exit 1
fi

INSTALLER="$(dirname "$0")/install.sh"
if [[ ! -f "${INSTALLER}" ]]; then
    echo "ERROR: no se encontró deploy/install.sh" >&2
    exit 1
fi

echo "[deploy] Compilando para linux/amd64 (estático)..."
cd "${REPO_ROOT}"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BINARY}" .

chmod +x "${INSTALLER}"

echo "[deploy] Subiendo a ${REMOTE}:~/ ..."
rsync -avz --progress --perms "${BINARY}" "${INSTALLER}" "${REMOTE}:~/"

echo ""
echo "[deploy] OK — binario e instalador subidos a ${REMOTE}:~/"
echo ""
echo "  Archivos depositados:"
echo "    ~/security-manager-ng   (binario)"
echo "    ~/install.sh            (instalador)"
echo ""
echo "  Siguiente paso:"
echo ""
echo "    ssh \${REMOTE}"
echo "    ~/install.sh"
echo ""
