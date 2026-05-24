#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  HADES PENDRIVE BUILDER v1.2.0
#  Construye un pendrive autónomo: HADES + Ollama + Modelos
#
#  USO:
#    bash build_pendrive.sh           → construye en ~/hades_pendrive/
#    bash build_pendrive.sh /mnt/usb  → construye directo en el pendrive
# ═══════════════════════════════════════════════════════════════════

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

HADES_VERSION="1.2.0"
BUILD_DIR="${1:-$HOME/hades_pendrive}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

echo -e "${RED}${BOLD}"
cat << 'BANNER'
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
BANNER
echo -e "${NC}${CYAN}        PENDRIVE BUILDER v${HADES_VERSION}${NC}"
echo ""
info "Destino: $BUILD_DIR"

command -v python3 &>/dev/null || err "Python3 requerido."
command -v curl    &>/dev/null || err "curl requerido: apt install curl"

# ── Estructura ───────────────────────────────────────────────────
mkdir -p "$BUILD_DIR"/{models,tools,logs,reports,scripts}
log "Estructura creada."

# ════════════════════════════════════════════════════════════════
# PASO 1 — Ollama portable
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━ [1/5] Ollama portable ━━━${NC}"
OLLAMA_BIN="$BUILD_DIR/ollama"
if [ ! -f "$OLLAMA_BIN" ]; then
    info "Descargando Ollama binary x86_64..."
    curl -L "https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64" \
        -o "$OLLAMA_BIN" --progress-bar
    chmod +x "$OLLAMA_BIN"
    log "Ollama: $(du -sh $OLLAMA_BIN | cut -f1)"
else
    log "Ollama ya descargado."
fi

# ════════════════════════════════════════════════════════════════
# PASO 2 — Modelos de IA
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━ [2/5] Modelos de IA ━━━${NC}"
export OLLAMA_MODELS="$BUILD_DIR/models"

# Copiar modelos locales si existen
LOCAL_MODELS="$HOME/.ollama/models"
if [ -d "$LOCAL_MODELS" ] && [ "$(ls -A $LOCAL_MODELS)" ]; then
    info "Copiando modelos locales al pendrive..."
    cp -r "$LOCAL_MODELS/"* "$BUILD_DIR/models/" 2>/dev/null || true
    log "Modelos copiados: $(du -sh $BUILD_DIR/models | cut -f1)"
else
    warn "No hay modelos locales. Descargando qwen2.5:3b como fallback..."
    # Iniciar Ollama temporal en puerto alternativo
    OLLAMA_MODELS="$BUILD_DIR/models" "$OLLAMA_BIN" serve &
    OTMP_PID=$!
    sleep 6
    OLLAMA_HOST="127.0.0.1:11434" "$OLLAMA_BIN" pull qwen2.5:3b && \
        log "qwen2.5:3b descargado." || warn "Descarga fallida."
    kill $OTMP_PID 2>/dev/null || true
fi
log "Modelos listos: $(du -sh $BUILD_DIR/models | cut -f1)"

# ════════════════════════════════════════════════════════════════
# PASO 3 — hades.sh (bash portable, el más compatible)
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━ [3/5] Ejecutable hades.sh ━━━${NC}"

cat > "$BUILD_DIR/hades.sh" << 'SHEOF'
#!/bin/bash
# HADES-LOCAL — Ejecutable bash portable
SCRIPT_PATH="$(readlink -f "$0")"
PENDRIVE="$(dirname "$SCRIPT_PATH")"
OLLAMA_BIN="$PENDRIVE/ollama"
HADES_PY="$PENDRIVE/hades_local.py"
HADES_LOG="$PENDRIVE/logs/hades.log"
REPORTS_DIR="$PENDRIVE/reports"

export OLLAMA_MODELS="$PENDRIVE/models"
mkdir -p "$PENDRIVE/logs" "$REPORTS_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Detectar Ollama disponible
OLLAMA_URL="http://127.0.0.1:11434/api/generate"
OLLAMA_STARTED=false

if curl -s --connect-timeout 2 "http://127.0.0.1:11434/api/tags" &>/dev/null; then
    echo -e "${GREEN}[OK]${NC} Ollama del sistema activo en :11434"
elif curl -s --connect-timeout 2 "http://127.0.0.1:11435/api/tags" &>/dev/null; then
    OLLAMA_URL="http://127.0.0.1:11435/api/generate"
    echo -e "${GREEN}[OK]${NC} Ollama del pendrive activo en :11435"
elif [ -f "$OLLAMA_BIN" ]; then
    echo -e "${YELLOW}[INFO]${NC} Iniciando Ollama desde pendrive..."
    OLLAMA_MODELS="$PENDRIVE/models" "$OLLAMA_BIN" serve --port 11435 \
        >> "$HADES_LOG" 2>&1 &
    echo $! > "$PENDRIVE/logs/ollama.pid"
    sleep 5
    OLLAMA_URL="http://127.0.0.1:11435/api/generate"
    OLLAMA_STARTED=true
    echo -e "${GREEN}[OK]${NC} Ollama iniciado desde pendrive"
else
    echo -e "${RED}[ERROR]${NC} Ollama no encontrado. Instala Ollama primero."
    exit 1
fi

# Crear script temporal con URL correcta y REPORT_DIR del pendrive
HADES_TMP="/tmp/hades_pendrive_$$.py"
sed "s|http://172\.[0-9.]*:11434/api/generate|$OLLAMA_URL|g;
     s|http://localhost:11434/api/generate|$OLLAMA_URL|g;
     s|Path.home() / \"hades_reports\"|Path(\"$REPORTS_DIR\")|g" \
    "$HADES_PY" > "$HADES_TMP"

cleanup() {
    rm -f "$HADES_TMP"
    if [ "$OLLAMA_STARTED" = true ] && [ -f "$PENDRIVE/logs/ollama.pid" ]; then
        kill $(cat "$PENDRIVE/logs/ollama.pid") 2>/dev/null || true
        rm -f "$PENDRIVE/logs/ollama.pid"
        echo -e "${YELLOW}[INFO]${NC} Ollama detenido."
    fi
}
trap cleanup EXIT INT TERM

python3 "$HADES_TMP" "$@"
SHEOF

chmod +x "$BUILD_DIR/hades.sh"
log "hades.sh creado"

# ════════════════════════════════════════════════════════════════
# PASO 4 — hades.bin con PyInstaller
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━ [4/5] Compilar hades.bin (PyInstaller) ━━━${NC}"

# Instalar PyInstaller si no está
if ! python3 -m PyInstaller --version &>/dev/null 2>&1; then
    info "Instalando PyInstaller..."
    pip3 install pyinstaller --quiet --break-system-packages 2>/dev/null || \
    pip3 install pyinstaller --quiet 2>/dev/null || true
fi

if python3 -m PyInstaller --version &>/dev/null 2>&1; then
    info "Compilando hades.bin..."
    cd /tmp
    python3 -m PyInstaller \
        --onefile \
        --name hades \
        --strip \
        --clean \
        --distpath "$BUILD_DIR" \
        --workpath /tmp/hades_pyinstaller_work \
        --specpath /tmp \
        --hidden-import urllib.request \
        --hidden-import urllib.error \
        "$SCRIPT_DIR/hades_local.py" 2>&1 | tail -8

    if [ -f "$BUILD_DIR/hades" ]; then
        mv "$BUILD_DIR/hades" "$BUILD_DIR/hades.bin"
        chmod +x "$BUILD_DIR/hades.bin"
        log "hades.bin: $(du -sh $BUILD_DIR/hades.bin | cut -f1)"
    else
        warn "PyInstaller no generó binario. Creando wrapper..."
        printf '#!/bin/bash\nDIR="$(dirname "$(readlink -f "$0")")"\nexec bash "$DIR/hades.sh" "$@"\n' \
            > "$BUILD_DIR/hades.bin"
        chmod +x "$BUILD_DIR/hades.bin"
    fi
else
    warn "PyInstaller no disponible. hades.bin será wrapper de hades.sh"
    printf '#!/bin/bash\nDIR="$(dirname "$(readlink -f "$0")")"\nexec bash "$DIR/hades.sh" "$@"\n' \
        > "$BUILD_DIR/hades.bin"
    chmod +x "$BUILD_DIR/hades.bin"
fi

# ════════════════════════════════════════════════════════════════
# PASO 5 — hades.AppImage
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━ [5/5] Crear hades.AppImage ━━━${NC}"

APPDIR="/tmp/HADES.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"

cp "$SCRIPT_DIR/hades_local.py" "$APPDIR/usr/bin/"

cat > "$APPDIR/AppRun" << 'APPEOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
PENDRIVE="$(dirname "$HERE")"
exec bash "$PENDRIVE/hades.sh" "$@"
APPEOF
chmod +x "$APPDIR/AppRun"

cat > "$APPDIR/hades.desktop" << 'DEOF'
[Desktop Entry]
Name=HADES Security Agent
Exec=AppRun
Icon=hades
Type=Application
Categories=Security;Network;
Terminal=true
DEOF

# Icono placeholder
printf 'P2\n1 1\n1\n0\n' > "$APPDIR/hades.png" 2>/dev/null || true

APPIMAGETOOL="/tmp/appimagetool-x86_64.AppImage"
if [ ! -f "$APPIMAGETOOL" ]; then
    info "Descargando appimagetool..."
    curl -L "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -o "$APPIMAGETOOL" --progress-bar 2>/dev/null && \
        chmod +x "$APPIMAGETOOL" || warn "No se pudo descargar appimagetool"
fi

if [ -f "$APPIMAGETOOL" ] && [ -x "$APPIMAGETOOL" ]; then
    ARCH=x86_64 "$APPIMAGETOOL" --no-appstream "$APPDIR" \
        "$BUILD_DIR/hades.AppImage" 2>/dev/null && \
        log "hades.AppImage: $(du -sh $BUILD_DIR/hades.AppImage | cut -f1)" || {
        warn "AppImage falló. Usando wrapper."
        cp "$BUILD_DIR/hades.sh" "$BUILD_DIR/hades.AppImage"
    }
else
    warn "appimagetool no disponible. hades.AppImage = wrapper de hades.sh"
    cp "$BUILD_DIR/hades.sh" "$BUILD_DIR/hades.AppImage"
fi
chmod +x "$BUILD_DIR/hades.AppImage"

# ════════════════════════════════════════════════════════════════
# Copiar fuente Python
# ════════════════════════════════════════════════════════════════
cp "$SCRIPT_DIR/hades_local.py" "$BUILD_DIR/hades_local.py"

# ════════════════════════════════════════════════════════════════
# Lanzador inteligente
# ════════════════════════════════════════════════════════════════
cat > "$BUILD_DIR/launch.sh" << 'LAUNCHEOF'
#!/bin/bash
# HADES — Lanzador inteligente (elige el mejor formato disponible)
DIR="$(dirname "$(readlink -f "$0")")"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
echo -e "${RED}"; cat "$DIR/.banner" 2>/dev/null; echo -e "${NC}"

if [ -f "$DIR/hades.bin" ] && file "$DIR/hades.bin" 2>/dev/null | grep -q "ELF"; then
    echo -e "${GREEN}[LAUNCH]${NC} hades.bin (compilado PyInstaller)"
    exec "$DIR/hades.bin" "$@"
elif [ -f "$DIR/hades.AppImage" ] && file "$DIR/hades.AppImage" 2>/dev/null | grep -q "ELF"; then
    echo -e "${GREEN}[LAUNCH]${NC} hades.AppImage"
    exec "$DIR/hades.AppImage" "$@"
elif [ -f "$DIR/hades.sh" ]; then
    echo -e "${GREEN}[LAUNCH]${NC} hades.sh (bash portable)"
    exec bash "$DIR/hades.sh" "$@"
elif command -v python3 &>/dev/null && [ -f "$DIR/hades_local.py" ]; then
    echo -e "${YELLOW}[LAUNCH]${NC} Fallback python3"
    exec python3 "$DIR/hades_local.py" "$@"
else
    echo -e "${RED}[ERROR]${NC} No se encontró ejecutable de HADES."
    exit 1
fi
LAUNCHEOF
chmod +x "$BUILD_DIR/launch.sh"

# Banner file para el lanzador
cat > "$BUILD_DIR/.banner" << 'BANNEREOF'
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
      PENDRIVE EDITION — HADES-LOCAL v1.2.0
BANNEREOF

# ════════════════════════════════════════════════════════════════
# INICIO.md para el pendrive
# ════════════════════════════════════════════════════════════════
cat > "$BUILD_DIR/INICIO.md" << 'INITEOF'
# HADES PENDRIVE EDITION

100% portable. Sin internet. Sin instalación.

## Primer uso

```bash
# Dar permisos (solo primera vez)
chmod +x launch.sh hades.sh hades.bin hades.AppImage ollama

# Lanzar agente (detecta el mejor formato automáticamente)
./launch.sh start
```

## Comandos

```bash
./launch.sh start                     # Shell interactivo
./launch.sh start --auto              # Modo autónomo
./launch.sh scan 192.168.1.1          # Escaneo rápido
./launch.sh fullaudit 192.168.1.0/24  # Auditoría completa
./launch.sh status                    # Estado
./launch.sh tools                     # Herramientas detectadas
```

## Formatos disponibles

| Archivo | Tipo | Compatibilidad |
|---------|------|---------------|
| launch.sh | Lanzador inteligente | Universal |
| hades.sh | Bash portable | Cualquier Linux |
| hades.bin | Compilado PyInstaller | x86_64 |
| hades.AppImage | AppImage | x86_64 |
| ollama | Motor IA portable | x86_64 |

## Reportes
Los reportes se guardan en `reports/` dentro del pendrive.

## Autor
Fabián Hormaz ábal | @LordHades268
INITEOF

# ════════════════════════════════════════════════════════════════
# RESUMEN
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BOLD}══════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}      HADES PENDRIVE BUILD COMPLETO       ${NC}"
echo -e "${RED}${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Destino: $BUILD_DIR${NC}"
echo ""
ls -lh "$BUILD_DIR" | grep -v "^total\|^d" | \
    awk '{printf "  %-25s %s\n", $NF, $5}'
echo ""
echo -e "  ${CYAN}Tamaño total: $(du -sh $BUILD_DIR | cut -f1)${NC}"
echo ""
echo -e "${YELLOW}Para copiar al pendrive USB:${NC}"
echo ""
echo "  lsblk                              # ver tu pendrive"
echo "  sudo mount /dev/sdb1 /mnt/usb     # montar"
echo "  cp -r $BUILD_DIR/* /mnt/usb/       # copiar"
echo "  chmod +x /mnt/usb/*.sh /mnt/usb/*.bin /mnt/usb/ollama"
echo "  sudo umount /mnt/usb               # desmontar"
echo ""
echo -e "${GREEN}¡Pendrive listo para cualquier Linux x86_64!${NC}"
