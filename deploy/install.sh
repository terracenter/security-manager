#!/usr/bin/env bash
# Instalador de security-manager-ng — ejecutar como usuario normal (usa sudo internamente)
set -e

BINARY="security-manager-ng"
DEST="/usr/local/sbin/${BINARY}"
SRC="${HOME}/${BINARY}"

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
