#!/bin/bash
# script-dev/install.sh — Instalador de SM-NG desde la rama `dev` (modo desarrollo).
#
# Diferencia con main:
#   - main: tags v* (estables), firma GPG. Aun no tiene un instalador propio.
#   - dev:  tags v0.8.0-dev.N (pre-release, sin GPG), install via este script.
#
# Ambos tienen CI/CD. dev produce Releases pre-release cuando vos pusheas
# el tag v0.8.0-dev.N a origin. workflow: .github/workflows/dev-release.yml.
#
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/terracenter/security-manager/dev/script-dev/install.sh | bash
#
# Que hace:
#   1. Banner grande: imprime "ESTO ES DEV — puede tener BUGs" en stderr/color.
#   2. Consulta la API publica de GitHub para encontrar el ultimo Release pre-release
#      con tag que matche v0.8.0-dev.*.
#   3. Descarga el binario y el .sha256 desde el Release.
#   4. Verifica el SHA256 (NO verifica GPG — los tags de dev no estan firmados).
#   5. Pide sudo para instalar en /usr/local/sbin/security-manager-ng-dev.
#
# Politica respetada: dev y main tienen CI/CD. Dev NO firma con GPG
# (esa validacion es solo para tags v* de main). Dev SI genera el binario
# compilado via GitHub Actions.

set -e

REPO="terracenter/security-manager"
BINARY="security-manager-ng"
DEST="/usr/local/sbin/${BINARY}-dev"

# ── Banner de advertencia (BIG — imprime esto primero, sin importar nada más) ──
# Quien corre este script debe entender inmediatamente que esta en dev.
# NO continuar si no esta seguro.
echo >&2
cat >&2 <<'EOF'
================================================================
   !!! ATENCION: INSTALADOR DE DESARROLLO (rama: dev) !!!
================================================================

  Este binario es de la rama `dev` de Security-Manager-NG y puede
  tener BUGS. NO es estable. NO recomendado para produccion.

  Esta corriendo una PRE-RELEASE generada automaticamente al pushear
  un tag v0.8.0-dev.N al repo. La firma GPG NO se valida (la firma
  GPG es exclusiva de los tags v* de produccion en main).

  Uso esperado: hosts de prueba, desarrollo, experimentacion.
================================================================
EOF
echo >&2

# ── Verificar dependencias ─────────────────────────────────────────────────
for dep in curl sha256sum sudo; do
    if ! command -v "${dep}" &>/dev/null; then
        echo "ERROR: falta '${dep}'" >&2
        exit 1
    fi
done

# ── Verificar que NO somos root ─────────────────────────────────────────────
if [[ ${EUID} -eq 0 ]]; then
    echo "ERROR: no ejecutes como root directo. El script usa sudo internamente." >&2
    exit 1
fi

# ── Encontrar el ultimo Release pre-release con tag v0.8.0-dev.* ──────────
echo '[script-dev] Buscando ultimo Release pre-release con tag v0.8.0-dev.*...'
RELEASES=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=30")

# Filtrar tags que matchean v0.8.0-dev.* y son prerelease=true
LATEST_TAG=$(echo "${RELEASES}" \
    | grep -oE '"tag_name":[[:space:]]*"v0\.8\.0-dev\.[0-9]+"' \
    | head -1 \
    | grep -oE 'v0\.8\.0-dev\.[0-9]+' || true)

if [[ -z "${LATEST_TAG}" ]]; then
    echo "ERROR: no encontre ningun Release pre-release con tag v0.8.0-dev.*" >&2
    echo "       Crea el primer tag con:" >&2
    echo "         git tag v0.8.0-dev.1" >&2
    echo "         git push origin v0.8.0-dev.1" >&2
    echo "       Eso dispara el workflow de CI en main y crea el Release." >&2
    exit 1
fi
echo '[script-dev] Tag encontrado:' "${LATEST_TAG}"

# ── Encontrar los asset_urls del release ────────────────────────────────────
RELEASE_INFO=$(echo "${RELEASES}" | tr '\n' '\0' \
    | sed -n "/${LATEST_TAG}/,/}/p" \
    | tr '\0' '\n' \
    | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
    | head -2 \
    | grep -oE '"https://[^"]+"' \
    | tr -d '"' || true)

BIN_URL=$(echo "${RELEASE_INFO}" | grep -E "/${BINARY}\"" | head -1)
SHA_URL=$(echo "${RELEASE_INFO}" | grep -E "/${BINARY}\.sha256\"" | head -1)

# Fallback: si el grep anterior fallo (porque grep -oE no captura bien), uso python
if [[ -z "${BIN_URL}" || -z "${SHA_URL}" ]]; then
    BIN_URL=$(echo "${RELEASES}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data:
    if r.get('tag_name', '').startswith('v0.8.0-dev.'):
        for a in r.get('assets', []):
            if a['name'] == '${BINARY}':
                print(a['browser_download_url'])
                break
        break
" 2>/dev/null || true)
    SHA_URL=$(echo "${RELEASES}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data:
    if r.get('tag_name', '').startswith('v0.8.0-dev.'):
        for a in r.get('assets', []):
            if a['name'] == '${BINARY}.sha256':
                print(a['browser_download_url'])
                break
        break
" 2>/dev/null || true)
fi

if [[ -z "${BIN_URL}" ]]; then
    echo "ERROR: no encontre el binario en el release ${LATEST_TAG}." >&2
    exit 1
fi

# ── Descargar ───────────────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
BIN_PATH="${TMP_DIR}/${BINARY}"
SHA_PATH="${TMP_DIR}/${BINARY}.sha256"

echo '[script-dev] Descargando binario desde el release' "${LATEST_TAG}" '...'
if ! curl -fsSL -o "${BIN_PATH}" "${BIN_URL}"; then
    echo "ERROR: no se pudo descargar ${BINARY} desde ${BIN_URL}" >&2
    exit 1
fi

if [[ -n "${SHA_URL}" ]]; then
    echo '[script-dev] Descargando SHA256...'
    if ! curl -fsSL -o "${SHA_PATH}" "${SHA_URL}"; then
        echo "WARN: no se pudo descargar el SHA256, saltando verificacion." >&2
    fi
fi

# ── Verificar SHA256 ────────────────────────────────────────────────────────
if [[ -f "${SHA_PATH}" ]]; then
    echo '[script-dev] Verificando SHA256...'
    if ! ( cd "${TMP_DIR}" && sha256sum -c "${BINARY}.sha256" ); then
        echo "ERROR: el checksum no coincide. Abortando." >&2
        exit 1
    fi
    echo '[script-dev] SHA256 verificado.'
fi

# ── Instalar con sudo ──────────────────────────────────────────────────────
echo '[script-dev] Instalando en' "${DEST}" '...'
sudo install -m 755 "${BIN_PATH}" "${DEST}"
echo
echo '[script-dev] Binario instalado como:' "${BINARY}-dev"
echo '[script-dev] Tag del release:' "${LATEST_TAG}"
echo '[script-dev] Uso:'
echo "    sudo ${BINARY}-dev --version"
echo "    sudo ${BINARY}-dev --help"
echo "    sudo ${BINARY}-dev firewall estado"
echo
echo '[script-dev] LISTO. Binario de rama dev (pre-release) instalado arriba.'
