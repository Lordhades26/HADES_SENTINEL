#!/bin/bash
# ═══════════════════════════════════════════════════════
#  HADES-LOCAL — Instalador de herramientas de seguridad
#  Uso: sudo bash install_tools.sh
# ═══════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${RED}"
echo " ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗"
echo " ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝"
echo -e "${NC}${YELLOW}HADES-LOCAL — Instalando herramientas...${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Ejecuta con sudo: sudo bash install_tools.sh"
    exit 1
fi

echo -e "${YELLOW}[INFO]${NC} Actualizando repositorios..."
apt-get update -qq

echo -e "${YELLOW}[INFO]${NC} Instalando herramientas de seguridad..."
apt-get install -y nmap nikto tshark john hashcat aircrack-ng dirb netdiscover wget curl git openssl 2>/dev/null

echo ""
echo -e "${YELLOW}Verificando instalación:${NC}"
TOOLS="nmap nikto tshark john hashcat aircrack-ng dirb netdiscover"
for tool in $TOOLS; do
    if command -v $tool &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool"
    else
        echo -e "  ${RED}[FALTA]${NC} $tool"
    fi
done

echo ""
echo -e "${GREEN}[LISTO]${NC} Ejecuta: python3 hades_local.py status"
