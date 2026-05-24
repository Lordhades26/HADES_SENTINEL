#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  HADES-LOCAL — Desinstalador v1.2.0
#  Elimina el agente del equipo de forma limpia.
#
#  USO:
#    bash uninstall.sh              → interactivo (pregunta qué borrar)
#    bash uninstall.sh --yes        → borra el agente sin preguntar
#                                     (conserva reportes y Ollama)
#    bash uninstall.sh --purge      → borra TODO: agente + reportes
#                                     + modelos + Ollama (pregunta 1 vez)
# ═══════════════════════════════════════════════════════════════════

set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
step() { echo -e "${BOLD}━━━ $1 ━━━${NC}"; }

ASSUME_YES=false
PURGE=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y)  ASSUME_YES=true ;;
        --purge)   PURGE=true; ASSUME_YES=true ;;
        -h|--help)
            grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) warn "Argumento desconocido: $arg" ;;
    esac
done

ask() {  # ask "pregunta"  → 0 si sí
    $ASSUME_YES && return 0
    read -r -p "$(echo -e "${YELLOW}[?]${NC} $1 [s/N] ")" r
    [[ "$r" =~ ^[sSyY]$ ]]
}

echo -e "${RED}${BOLD}"
cat << 'BANNER'
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
BANNER
echo -e "${NC}${CYAN}        DESINSTALADOR v1.2.0${NC}\n"

# ── Directorio de instalación ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR=""
for cand in "$SCRIPT_DIR" "$HOME/hades_local" "/root/hades_local" \
            "/opt/hades_local"; do
    if [ -f "$cand/hades_local.py" ]; then INSTALL_DIR="$cand"; break; fi
done
[ -z "$INSTALL_DIR" ] && warn "No se encontró hades_local.py; se limpiará lo demás igual."

info "Directorio detectado: ${INSTALL_DIR:-(ninguno)}"
echo ""

if ! $ASSUME_YES; then
    if ! ask "¿Desinstalar HADES-LOCAL de este equipo?"; then
        echo -e "${CYAN}Cancelado. No se borró nada.${NC}"; exit 0
    fi
fi

# ── 1. Detener proceso del agente ────────────────────────────────
step "[1/5] Deteniendo el agente"
KILLED=false
for pf in "$HOME/.hades_local.pid" /tmp/hades_local.pid \
          "${INSTALL_DIR:-/nonexistent}/.hades_local.pid"; do
    if [ -f "$pf" ]; then
        PID="$(cat "$pf" 2>/dev/null || true)"
        if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null && log "Proceso $PID detenido." && KILLED=true
        fi
        rm -f "$pf"
    fi
done
pkill -f "hades_local.py" 2>/dev/null && KILLED=true
$KILLED || info "No había agente en ejecución."

# ── 2. Logs y PID ────────────────────────────────────────────────
step "[2/5] Eliminando logs y PID"
rm -f "$HOME/.hades_local.log" "$HOME/.hades_local.pid" \
      /tmp/hades_local.log /tmp/hades_local.pid \
      /tmp/hades_pendrive_*.py 2>/dev/null || true
log "Logs y PID eliminados."

# ── 3. Symlink/comando global ────────────────────────────────────
step "[3/5] Eliminando comando global"
for link in /usr/local/bin/hades /usr/local/bin/hades_local \
            "$HOME/.local/bin/hades"; do
    if [ -L "$link" ] || [ -f "$link" ]; then
        if grep -q "hades_local" "$link" 2>/dev/null || \
           [ "$(readlink -f "$link" 2>/dev/null)" = \
             "${INSTALL_DIR:-/nonexistent}/hades_local.py" ]; then
            if [ -w "$(dirname "$link")" ]; then rm -f "$link"
            else sudo rm -f "$link" 2>/dev/null || true; fi
            log "Eliminado: $link"
        fi
    fi
done

# ── 4. Reportes ──────────────────────────────────────────────────
step "[4/5] Reportes generados"
REPORTS="$HOME/hades_reports"
[ -d /root/hades_reports ] && [ ! -d "$REPORTS" ] && REPORTS=/root/hades_reports
if [ -d "$REPORTS" ]; then
    N=$(find "$REPORTS" -type f 2>/dev/null | wc -l)
    if $PURGE || ask "Borrar también los reportes ($N archivos en $REPORTS)?"; then
        rm -rf "$REPORTS" && log "Reportes eliminados."
    else
        info "Reportes conservados en $REPORTS"
    fi
else
    info "No hay carpeta de reportes."
fi

# ── 5. Directorio del agente + Ollama opcional ───────────────────
step "[5/5] Archivos del agente"
if [ -n "$INSTALL_DIR" ] && [ -d "$INSTALL_DIR" ]; then
    # No borrar este propio script hasta el final; copiar a /tmp y continuar
    if [ "$SCRIPT_DIR" = "$INSTALL_DIR" ]; then
        cp "$0" /tmp/.hades_uninstall_self.sh 2>/dev/null || true
    fi
    if [ -w "$INSTALL_DIR" ]; then rm -rf "$INSTALL_DIR"
    else sudo rm -rf "$INSTALL_DIR" 2>/dev/null || rm -rf "$INSTALL_DIR"; fi
    log "Directorio del agente eliminado: $INSTALL_DIR"
fi

if command -v ollama &>/dev/null; then
    if $PURGE || ask "¿Desinstalar también Ollama y sus modelos? (afecta otros usos de Ollama)"; then
        sudo systemctl stop ollama 2>/dev/null || true
        sudo systemctl disable ollama 2>/dev/null || true
        sudo rm -f /etc/systemd/system/ollama.service 2>/dev/null || true
        sudo rm -f "$(command -v ollama)" 2>/dev/null || true
        rm -rf "$HOME/.ollama" 2>/dev/null || true
        sudo rm -rf /usr/share/ollama 2>/dev/null || true
        log "Ollama y modelos eliminados."
    else
        info "Ollama conservado (otros programas pueden usarlo)."
    fi
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   HADES-LOCAL desinstalado correctamente  ${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo -e "${CYAN}Gracias por usar HADES. Vuelve cuando quieras.${NC}"
rm -f /tmp/.hades_uninstall_self.sh 2>/dev/null || true
exit 0
