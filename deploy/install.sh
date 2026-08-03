#!/usr/bin/env bash
# Instalador de security-manager-ng — ejecutar como usuario normal (usa sudo internamente)
#
# Este script vive en el repo (versionado, auditable en GitHub). Instalación en un solo comando,
# como usuario normal — NUNCA con sudo por delante (el script se auto-aborta si detecta EUID 0,
# ver "Verificaciones previas" más abajo: exige usuario normal + sudo interno, no root directo):
#   curl -fsSL https://raw.githubusercontent.com/terracenter/security-manager-ng/dev/deploy/install.sh | SMNG_FROM_RELEASE=1 bash
#
# La verificación real de seguridad ocurre DENTRO de este script (firma GPG + checksum del
# binario, fingerprint fijo) — no depende de que revises el script antes de correrlo.
#
# El script pedirá tu password de sudo justo en el momento de copiar el binario a
# /usr/local/sbin — requiere terminal interactiva real (no funciona en CI/automation sin tty).
#
# Si prefieres auditar el script primero de todos modos:
#   curl -fsSL https://raw.githubusercontent.com/terracenter/security-manager-ng/dev/deploy/install.sh -o install.sh
#   less install.sh   # revisar antes de ejecutar
#   SMNG_FROM_RELEASE=1 bash install.sh
set -e

BINARY="security-manager-ng"
DEST="/usr/local/sbin/${BINARY}"
SRC="${HOME}/${BINARY}"

# Fingerprint fijo de la llave de firma de releases — el ancla real de confianza de este
# script: aunque la descarga de la llave pública (más abajo) fuera interceptada o el sitio
# que la aloja estuviera comprometido, si el fingerprint importado no coincide EXACTO con
# este valor, el script aborta. Ver Planes/Security-Manager-NG/gpg-firma-releases-guia.md
# (vault privado del mantenedor) para el procedimiento completo de generación/backup de
# esta llave. Verificable también de forma independiente en:
#   https://keys.openpgp.org/search?q=terracenter@gmail.com
#   https://gpg-key.humanbyte.net
SIGNING_KEY_FINGERPRINT="6D33CBB56A4FA1E2966C40225923730155062949"
GPG_KEY_URL="https://gpg-key.humanbyte.net/sm-ng-release-signing.pub.asc"

# ── Modo dev: descargar desde la rama `binarios-dev` del repo (sin GPG, con SHA256) ─────
# Modo para pruebas: el usuario acepta que el binario puede tener bugs porque es de dev.
# Se baja de raw.githubusercontent.com la rama `binarios-dev` (mantenida por el workflow
# .github/workflows/build-dev-binary.yml que compila en cada push a `dev`).
# Uso: SMNG_FROM_BRANCH=dev bash install.sh
if [[ "${SMNG_FROM_BRANCH:-}" != "" ]]; then
    BRANCH="${SMNG_FROM_BRANCH}"
    # Por ahora solo soportamos binarios-dev (la rama donde el workflow pushea).
    if [[ "${BRANCH}" != "binarios-dev" ]]; then
        echo "ERROR: SMNG_FROM_BRANCH=${BRANCH} no soportado. Usar 'binarios-dev'." >&2
        exit 1
    fi
    BASE="https://raw.githubusercontent.com/terracenter/Security-Manager-Ng/${BRANCH}"

    for dep in curl sha256sum; do
        if ! command -v "${dep}" &>/dev/null; then
            echo "ERROR: falta '${dep}' — necesario para descargar y verificar el binario." >&2
            exit 1
        fi
    done

    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    echo "[install] SMNG_FROM_BRANCH=${BRANCH}: descargando binario desde raw..."
    echo "[install] ADVERTENCIA: binario de rama dev, sin firma GPG. PUEDE TENER BUGS."

    for f in "${BINARY}" "${BINARY}.sha256"; do
        if ! curl -fsSL "${BASE}/${f}" -o "${TMP_DIR}/${f}"; then
            echo "ERROR: no se pudo descargar ${f} desde ${BASE}" >&2
            echo "       Verifica que el workflow build-dev-binary haya corrido en dev y subido a binarios-dev." >&2
            exit 1
        fi
    done

    echo "[install] Verificando SHA256 (sin GPG en modo dev)..."
    if ! ( cd "${TMP_DIR}" && sha256sum -c "${BINARY}.sha256" ); then
        echo "ERROR: el checksum no coincide. Abortando." >&2
        exit 1
    fi

    cp "${TMP_DIR}/${BINARY}" "${SRC}"
    chmod +x "${SRC}"
    echo "[install] Binario de ${BRANCH} verificado y listo en ${SRC}"
fi

# ── Modo alterno: descargar desde GitHub Release, con verificación GPG obligatoria ────────
if [[ "${SMNG_FROM_RELEASE}" == "1" ]]; then
    echo "[install] SMNG_FROM_RELEASE=1: descargando desde GitHub Release..."
    # Mientras no exista una release estable, "latest" no resuelve (GitHub excluye
    # pre-releases de /releases/latest) — usar la tag explícita y bumpear en cada release
    # nueva hasta que haya una estable, momento en que se puede volver a "latest".
    RELEASE_BASE="https://github.com/terracenter/security-manager-ng/releases/download/v0.7.0"

    for dep in curl gpg sha256sum; do
        if ! command -v "${dep}" &>/dev/null; then
            echo "ERROR: falta '${dep}' — necesario para descargar y verificar el release." >&2
            exit 1
        fi
    done

    TMP_DIR="$(mktemp -d)"
    GNUPGHOME_TMP="$(mktemp -d)"
    chmod 700 "${GNUPGHOME_TMP}"
    trap 'rm -rf "${TMP_DIR}" "${GNUPGHOME_TMP}"' EXIT

    echo "[install] Descargando binario, checksum y firma..."
    for f in "${BINARY}" "${BINARY}.sha256" "${BINARY}.asc"; do
        if ! curl -fsSL "${RELEASE_BASE}/${f}" -o "${TMP_DIR}/${f}"; then
            echo "ERROR: no se pudo descargar ${f} desde ${RELEASE_BASE}" >&2
            exit 1
        fi
    done

    echo "[install] Descargando llave pública de firma desde ${GPG_KEY_URL}..."
    if ! curl -fsSL "${GPG_KEY_URL}" -o "${TMP_DIR}/signing-key.pub.asc"; then
        echo "ERROR: no se pudo descargar la llave pública de firma." >&2
        echo "       Fuente independiente alterna: https://keys.openpgp.org/search?q=terracenter@gmail.com" >&2
        exit 1
    fi

    GNUPGHOME="${GNUPGHOME_TMP}" gpg --batch --import "${TMP_DIR}/signing-key.pub.asc" >/dev/null 2>&1
    IMPORTED_FPR="$(GNUPGHOME="${GNUPGHOME_TMP}" gpg --batch --with-colons --fingerprint 2>/dev/null \
        | awk -F: '/^fpr:/ {print $10; exit}')"

    echo "[install] Verificando fingerprint de la llave importada..."
    if [[ "${IMPORTED_FPR}" != "${SIGNING_KEY_FINGERPRINT}" ]]; then
        echo "ERROR: el fingerprint de la llave descargada NO coincide con el esperado." >&2
        echo "       Esperado: ${SIGNING_KEY_FINGERPRINT}" >&2
        echo "       Obtenido: ${IMPORTED_FPR:-<vacío>}" >&2
        echo "       Abortando — no se instala nada sin una firma verificable contra la llave correcta." >&2
        exit 1
    fi

    echo "[install] Verificando firma GPG del binario..."
    if ! GNUPGHOME="${GNUPGHOME_TMP}" gpg --batch --verify "${TMP_DIR}/${BINARY}.asc" "${TMP_DIR}/${BINARY}" 2>&1; then
        echo "ERROR: la firma GPG del binario no es válida. Abortando — no se instala nada." >&2
        exit 1
    fi
    echo "[install] Firma GPG verificada correctamente."

    echo "[install] Verificando checksum (defensa adicional)..."
    if ! ( cd "${TMP_DIR}" && sha256sum -c "${BINARY}.sha256" ); then
        echo "ERROR: el checksum no coincide. Abortando." >&2
        exit 1
    fi

    cp "${TMP_DIR}/${BINARY}" "${SRC}"
    chmod +x "${SRC}"
    echo "[install] Binario verificado y listo en ${SRC}"
fi

# ── Verificaciones previas ────────────────────────────────────────────────────

if [[ ${EUID} -eq 0 ]]; then
    echo "ERROR: no ejecutes como root directo. Hazlo como usuario normal — el script usa sudo internamente." >&2
    exit 1
fi

if [[ ! -f "${SRC}" ]]; then
    echo "ERROR: no se encontró ${BINARY} en ${HOME}/" >&2
    echo "       Ejecuta primero: bash deploy/deploy.sh <host>" >&2
    exit 1
fi

if ! command -v sudo &>/dev/null; then
    echo "ERROR: sudo no está disponible en este host" >&2
    exit 1
fi

if ! command -v nft &>/dev/null; then
    echo "[install] WARN: nftables (nft) no detectado — instálalo antes de usar el firewall"
fi

# ── Detectar primera instalación vs. actualización ───────────────────────────
INSTALACION_NUEVA=true
if [[ -f "${DEST}" ]]; then
    INSTALACION_NUEVA=false
fi

echo "[install] Iniciando instalación de ${BINARY}..."

# ── Instalar binario ──────────────────────────────────────────────────────────
echo "[install] Copiando a ${DEST}..."
sudo install -m 750 "${SRC}" "${DEST}"
sudo chown root:root "${DEST}"

echo "[install] Permisos aplicados:"
ls -lh "${DEST}"

# ── Post-instalación ──────────────────────────────────────────────────────────
if [[ "${INSTALACION_NUEVA}" == "true" ]]; then
    echo ""
    echo "[install] Primera instalación completada."
    echo "[install] Lanza el wizard de configuración inicial:"
    echo ""
    echo "    sudo security-manager-ng"
    echo ""
else
    echo ""
    echo "[install] Actualización completada."
    echo ""
    echo "    sudo security-manager-ng"
    echo ""
fi

# ── Limpiar archivos temporales del home ──────────────────────────────────────
echo "[install] Limpiando archivos temporales..."
rm -f "${HOME}/${BINARY}" "${HOME}/install.sh"

echo "[install] OK — ${BINARY} instalado en ${DEST}"
