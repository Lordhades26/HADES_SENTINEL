#!/usr/bin/env python3
"""
HADES SURVEILLANCE ADVANCED v2.1
Vigilancia autónoma de red completa.
Integra: Nmap ARP, Tshark (captura live), Nuclei web vuln, TLS audit, Ollama IA.

Flujo:
  FASE 1 → Descubrimiento ARP (Nmap)
  FASE 2 → Captura de tráfico de red (Tshark) — 30 segundos
  FASE 3 → Actualizar templates Nuclei
  FASE 4 → Auditoría completa por IP (Nmap deep + Nuclei + TLS + IA)
  FASE 5 → Guardar informes (individual por host + maestro .md)
"""
import os, sys, json, re, subprocess
from datetime import datetime
from collections import defaultdict

# Asegurar codificación UTF-8 en Windows para evitar UnicodeEncodeError al imprimir caracteres
if sys.platform.startswith('win') or os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Importar el motor principal
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from hades_win_master_advanced import HadesMCP, log, execute, WIN_PATHS

HADES_VERSION = "2.1.0"
TSHARK_BIN    = WIN_PATHS["tshark"]

# ─── DETECCIÓN AUTOMÁTICA DE INTERFAZ ACTIVA ──────────────────────────────────
def detect_active_interface():
    """
    Lista las interfaces Tshark y devuelve el nombre de la primera activa
    con tráfico real (Wi-Fi o Ethernet). Prioriza Wi-Fi, luego Ethernet.
    """
    out = execute(f'"{TSHARK_BIN}" -D', timeout=10)
    interfaces = []
    for line in out.splitlines():
        m = re.match(r'(\d+)\.\s+\S+\s+\((.+)\)', line.strip())
        if m:
            idx, name = m.group(1), m.group(2)
            interfaces.append((int(idx), name))

    # Prioridad: Wi-Fi > Ethernet (excluye virtuales/loopback/USB)
    exclude = ["loopback", "npcap", "usbpcap", "área local", "etw"]
    priority = ["wi-fi", "wifi", "ethernet"]

    for keyword in priority:
        for idx, name in interfaces:
            name_lower = name.lower()
            if keyword in name_lower and not any(ex in name_lower for ex in exclude):
                log(f"Interfaz detectada: [{idx}] {name}", "TSHARK")
                return name

    # Fallback: primera interfaz no virtual
    for idx, name in interfaces:
        if not any(ex in name.lower() for ex in exclude):
            log(f"Interfaz fallback: [{idx}] {name}", "TSHARK")
            return name

    log("No se pudo detectar interfaz activa. Usando 'Wi-Fi'.", "WARN")
    return "Wi-Fi"


# ─── ANÁLISIS DE CAPTURA TSHARK ───────────────────────────────────────────────
def parse_tshark_output(raw, active_ips):
    """
    Procesa la salida de Tshark en campos y devuelve un resumen estructurado.
    Identifica: conexiones activas, IPs externas, protocolos y puertos usados.
    """
    connections = defaultdict(int)
    external_ips = set()
    protocols = defaultdict(int)
    local_subnet = set()

    for line in raw.strip().splitlines():
        parts = line.strip().split('\t')
        if len(parts) < 5:
            continue
        src, dst, tcp_port, udp_port, proto = parts[0], parts[1], parts[2], parts[3], parts[4]
        port = tcp_port or udp_port or "?"
        proto = proto.strip() or "?"

        if src and dst:
            connections[(src, dst, port, proto)] += 1
            protocols[proto] += 1

            # Detectar IPs externas (no LAN 192.168.x.x / 10.x / 172.x)
            for ip in [src, dst]:
                if ip and not re.match(r'^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)', ip):
                    if not ip.startswith("127.") and ip != "0.0.0.0":
                        external_ips.add(ip)

    # Construir resumen legible
    lines = []
    lines.append(f"  Paquetes/conexiones capturadas: {sum(connections.values())}")
    lines.append(f"  Protocolos detectados: {dict(sorted(protocols.items(), key=lambda x: -x[1]))}")
    lines.append(f"  IPs externas (internet): {len(external_ips)}")

    if external_ips:
        lines.append("  IPs externas detectadas:")
        for eip in sorted(external_ips)[:20]:
            lines.append(f"    - {eip}")

    # Conexiones por host de la red local
    lines.append("\n  Actividad por host LAN detectado:")
    host_activity = defaultdict(list)
    for (src, dst, port, proto), count in connections.items():
        for ip in active_ips:
            if src == ip or dst == ip:
                partner = dst if src == ip else src
                host_activity[ip].append(f"{proto}:{port} → {partner} ({count}x)")

    for ip in active_ips:
        acts = host_activity.get(ip, [])
        if acts:
            lines.append(f"    [{ip}]: {', '.join(acts[:5])}")
        else:
            lines.append(f"    [{ip}]: sin tráfico capturado en este periodo")

    return "\n".join(lines)


# ─── CLASE PRINCIPAL ──────────────────────────────────────────────────────────
class HadesSurveillance:
    def __init__(self, output_base=None, target_range="192.168.1.0/24",
                 capture_seconds=30):
        self.mcp             = HadesMCP()
        self.output_base     = output_base or os.path.join(_HERE, "informes")
        self.target_range    = target_range
        self.capture_seconds = capture_seconds  # segundos de captura Tshark

    def run(self):
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M")
        report_dir = os.path.join(self.output_base, f"informe_{timestamp}")
        os.makedirs(report_dir, exist_ok=True)
        # Definido al inicio para poder guardar el informe de forma INCREMENTAL:
        # si la auditoría se interrumpe o un host falla, los resultados ya
        # obtenidos quedan persistidos (no se pierde todo al final).
        master_file = os.path.join(report_dir, "INFORME_MAESTRO.md")
        def _persist(txt):
            try:
                with open(master_file, 'w', encoding='utf-8') as f:
                    f.write(txt)
            except Exception as e:
                log(f"No se pudo guardar el informe parcial: {e}", "WARN")

        print(f"\n{'='*65}")
        print(f"  HADES SURVEILLANCE v{HADES_VERSION}")
        print(f"  Fecha:    {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        print(f"  Objetivo: {self.target_range}")
        print(f"  Informe:  {report_dir}")
        print(f"{'='*65}\n")

        # ── PRE-FLIGHT: comprobar herramientas para degradar con elegancia ──
        log("Pre-flight: comprobando herramientas disponibles...", "HADES")
        preflight = {
            "Nmap":    os.path.exists(WIN_PATHS["nmap"]),
            "Tshark":  os.path.exists(WIN_PATHS["tshark"]),
            "Nuclei":  os.path.exists(WIN_PATHS["nuclei"]),
            "OpenSSL": os.path.exists(WIN_PATHS["openssl"]),
            "Ollama":  self.mcp._ollama_available(),
        }
        for name, ok in preflight.items():
            log(f"  {name}: {'OK' if ok else 'NO DISPONIBLE (se omitirá su fase)'}",
                "OK" if ok else "WARN")
        if not preflight["Nmap"]:
            log("Nmap es imprescindible para el descubrimiento; abortando.", "WARN")
            return
        # Precargar el modelo IA en segundo plano para que las fases de análisis no
        # congelen el flujo (el modelo tarda en cargar la primera vez).
        if preflight["Ollama"]:
            self.mcp.warm_up_model()

        master_report  = f"# INFORME HADES SURVEILLANCE v{HADES_VERSION} — {timestamp}\n\n"
        master_report += "| Herramienta | Estado |\n|---|---|\n"
        for name, ok in preflight.items():
            master_report += f"| {name} | {'✅ Disponible' if ok else '⚠️ No disponible'} |\n"
        master_report += "\n"
        master_report += f"| Campo | Valor |\n|---|---|\n"
        master_report += f"| Red objetivo | `{self.target_range}` |\n"
        master_report += f"| Fecha | {datetime.now().strftime('%d/%m/%Y %H:%M')} |\n"

        # ══════════════════════════════════════════════════════════════════════
        # FASE 1 — DESCUBRIMIENTO ARP
        # ══════════════════════════════════════════════════════════════════════
        log("FASE 1 — Descubrimiento ARP (Nmap)...", "HADES")
        discovery_out = self.mcp.nmap_discovery(self.target_range)
        active_ips = re.findall(
            r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            discovery_out
        )

        if not active_ips:
            log("Sin hosts activos. Verifica el rango de red.", "WARN")
            return

        log(f"Detectados {len(active_ips)} dispositivo(s): {active_ips}", "OK")
        master_report += f"| Dispositivos activos | {len(active_ips)} |\n"
        master_report += f"| IPs | {', '.join(f'`{ip}`' for ip in active_ips)} |\n\n---\n\n"
        master_report += f"## Fase 1 — Descubrimiento ARP\n```\n{discovery_out[:1500]}\n```\n\n---\n\n"

        # ══════════════════════════════════════════════════════════════════════
        # FASE 2 — CAPTURA DE TRÁFICO (TSHARK)
        # ══════════════════════════════════════════════════════════════════════
        log(f"FASE 2 — Captura de tráfico Tshark ({self.capture_seconds}s)...", "HADES")

        interface = detect_active_interface()

        # Capturar campos: ip.src, ip.dst, tcp.dstport, udp.dstport, protocolo
        tshark_cmd = (
            f'"{TSHARK_BIN}" -i "{interface}" '
            f'-a duration:{self.capture_seconds} '
            f'-T fields '
            f'-e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol '
            f'-E separator=/t'  # '/t' = tabulador en notación tshark; un '\\t' literal hacía fallar a tshark
        )
        log(f"Capturando en [{interface}] durante {self.capture_seconds}s...", "TSHARK")
        tshark_raw = execute(tshark_cmd, timeout=self.capture_seconds + 15)

        tshark_summary = parse_tshark_output(tshark_raw, active_ips)
        log("Captura completada.", "OK")
        log(f"Resumen tráfico:\n{tshark_summary}", "TSHARK")

        # Guardar pcap de texto
        tshark_file = os.path.join(report_dir, "trafico_red.txt")
        with open(tshark_file, 'w', encoding='utf-8') as f:
            f.write(f"CAPTURA TSHARK — {timestamp}\n")
            f.write(f"Interfaz: {interface} | Duración: {self.capture_seconds}s\n\n")
            f.write("=== RESUMEN ===\n")
            f.write(tshark_summary + "\n\n")
            f.write("=== DATOS RAW ===\n")
            f.write(tshark_raw)

        master_report += f"## Fase 2 — Captura de Tráfico (Tshark)\n"
        master_report += f"**Interfaz:** `{interface}` | **Duración:** {self.capture_seconds}s\n\n"
        master_report += f"```\n{tshark_summary}\n```\n\n---\n\n"

        # Análisis IA del tráfico capturado (se omite si no hubo tráfico → evita
        # una llamada IA lenta e inútil, que es lo que congeló el escaneo anterior).
        if "capturadas: 0" in tshark_summary:
            log("Sin tráfico capturado; se omite el análisis IA del tráfico.", "HADES")
            ia_trafico = "Sin tráfico capturado durante el periodo; análisis IA omitido."
        else:
            log("Analizando tráfico con IA...", "HADES")
            ia_trafico = self.mcp.ai_analysis(
                f"Eres HADES, agente de ciberseguridad. Analiza este tráfico de red capturado "
                f"en la red {self.target_range} durante {self.capture_seconds} segundos. "
                f"Identifica comportamientos sospechosos, conexiones no autorizadas, "
                f"protocolos inusuales y riesgos potenciales:\n\n{tshark_summary}"
            )
        master_report += f"### Análisis IA del Tráfico\n{ia_trafico}\n\n---\n\n"

        # ══════════════════════════════════════════════════════════════════════
        # FASE 3 — ACTUALIZAR TEMPLATES NUCLEI
        # ══════════════════════════════════════════════════════════════════════
        log("FASE 3 — Actualizando templates de Nuclei...", "HADES")
        self.mcp.nuclei_update_templates()

        # ══════════════════════════════════════════════════════════════════════
        # PRESENTACIÓN DE OPCIONES DE ESCANEO AL PENTESTER
        # ══════════════════════════════════════════════════════════════════════
        print(f"\n{'-'*65}")
        print("  HADES SURVEILLANCE — DISPOSITIVOS ACTIVOS DETECTADOS")
        print(f"{'-'*65}")
        for idx, ip in enumerate(active_ips, 1):
            print(f"  [{idx}] IP: {ip}")
        print(f"  [A] Escanear TODOS los hosts de la red de forma automatica")
        print(f"  [Q] Salir de HADES")
        print(f"{'-'*65}\n")

        chosen_ips = []
        if os.environ.get("HADES_NON_INTERACTIVE") == "1" or not sys.stdin.isatty():
            log("Modo no-interactivo detectado. Escaneando todos los hosts detectados automáticamente.", "HADES")
            chosen_ips = active_ips
        else:
            while True:
                choice = input("Selecciona una opcion (ID de host, 'A' para todos, 'Q' para salir): ").strip().upper()
                if choice == 'Q':
                    log("Saliendo de HADES. No se realizaron auditorias profundas de hosts.", "HADES")
                    return
                elif choice == 'A':
                    chosen_ips = active_ips
                    log("Opcion seleccionada: Auditoria completa de TODA la red.", "HADES")
                    break
                else:
                    try:
                        num = int(choice)
                        if 1 <= num <= len(active_ips):
                            selected_ip = active_ips[num - 1]
                            chosen_ips = [selected_ip]
                            log(f"Opcion seleccionada: Escaneo enfocado del host {selected_ip}", "HADES")
                            break
                        else:
                            print(f"[ERROR] Por favor ingresa un numero valido entre 1 y {len(active_ips)}.")
                    except ValueError:
                        print("[ERROR] Entrada no reconocida. Escribe el numero del host, 'A' o 'Q'.")

        # ══════════════════════════════════════════════════════════════════════
        # FASE 4 — AUDITORÍA COMPLETA POR IP (FILTRADA)
        # ══════════════════════════════════════════════════════════════════════
        log("FASE 4 — Auditoría individual por objetivo...", "HADES")
        master_report += f"## Fase 4 — Auditorias por Host (Objetivos seleccionados: {', '.join(chosen_ips)})\n\n"
        _persist(master_report)  # guardar progreso hasta aquí (fases 1-3)

        audited_ok = 0
        for idx, ip in enumerate(chosen_ips, 1):
            log(f"[{idx}/{len(chosen_ips)}] Auditoria completa → {ip}", "SCAN")
            try:
                # Nmap deep + Nuclei web + TLS + IA
                full_report = self.mcp.full_audit(ip)
                master_report += full_report + "\n\n---\n\n"
                audited_ok += 1
                log(f"Host {ip} auditado y consolidado en el informe único.", "OK")
            except Exception as e:
                # ROBUSTEZ: el fallo de UN host no aborta la auditoría completa.
                err = f"\n[ERROR] La auditoría del host {ip} falló: {e}\n"
                master_report += f"## Host {ip}\n{err}\n---\n\n"
                log(f"Host {ip} falló ({e}); continuando con el resto.", "WARN")
            # Guardado INCREMENTAL tras cada host: si algo revienta después,
            # lo ya auditado queda en disco.
            _persist(master_report)

        # ══════════════════════════════════════════════════════════════════════
        # FASE 5 — INFORME MAESTRO (flush final)
        # ══════════════════════════════════════════════════════════════════════
        _persist(master_report)

        # ══════════════════════════════════════════════════════════════════════
        # FASE 6 — INFORME EJECUTIVO ISO/IEC 27001 (DOCX)
        # ══════════════════════════════════════════════════════════════════════
        docx_file = None
        try:
            log("FASE 6 — Generando informe ejecutivo ISO 27001 (.docx)...", "HADES")
            from hades_report_docx import generate_from_master
            docx_file = generate_from_master(master_file)
            log(f"Informe ejecutivo DOCX generado: {docx_file}", "OK")
        except ImportError:
            log("python-docx no instalado; se omite el .docx (informe .md disponible). "
                "Instala con: pip install python-docx", "WARN")
        except Exception as e:
            log(f"No se pudo generar el .docx ({e}); el informe .md queda disponible.", "WARN")

        print(f"\n{'='*65}")
        print(f"  [HADES] Vigilancia v{HADES_VERSION} completada.")
        print(f"  Fase 1 — Dispositivos detectados : {len(active_ips)}")
        print(f"  Fase 2 — Tráfico capturado       : {self.capture_seconds}s en [{interface}]")
        print(f"  Fase 3 — Templates Nuclei         : verificados")
        print(f"  Fase 4 — Hosts auditados OK       : {audited_ok}/{len(chosen_ips)}")
        print(f"  Informe consolidado (.md) : {master_file}")
        if docx_file:
            print(f"  Informe ejecutivo (.docx) : {docx_file}")
        print(f"  Carpeta                   : {report_dir}")
        print(f"{'='*65}\n")


# ─── FUNCIONES DE AUTODETECCIÓN DE RED ─────────────────────────────────────────
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No requiere conexión real a internet, solo inicializar la interfaz de enrutamiento
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def detect_local_subnet():
    ip = get_local_ip()
    if ip == '127.0.0.1':
        log("No se pudo detectar una dirección IP activa en la interfaz. Usando rango por defecto.", "WARN")
        return "192.168.1.0/24"
    parts = ip.split('.')
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    log(f"Red local autodetectada a través de la IP {ip}: {subnet}", "OK")
    return subnet


# ─── PUNTO DE ENTRADA ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    TARGET_RANGE     = "192.168.1.0/24"
    OUTPUT_DIR       = os.path.join(_HERE, "informes")
    CAPTURE_SECONDS  = 30   # segundos de captura Tshark — ajustar según necesidad

    if len(sys.argv) > 1:
        val = sys.argv[1].strip()
        if not val or val.lower() in ("auto", "detect", "autodetect"):
            TARGET_RANGE = detect_local_subnet()
        else:
            TARGET_RANGE = val
    else:
        # Si no se pasan argumentos, autodetectar por defecto
        TARGET_RANGE = detect_local_subnet()

    if len(sys.argv) > 2:
        CAPTURE_SECONDS = int(sys.argv[2])

    agent = HadesSurveillance(
        output_base=OUTPUT_DIR,
        target_range=TARGET_RANGE,
        capture_seconds=CAPTURE_SECONDS
    )
    agent.run()
