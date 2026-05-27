#!/usr/bin/env python3
"""
HADES WIN MASTER ADVANCED v2.0
Motor principal del agente HADES para Windows.
Integra: Nmap (ARP), Nuclei (web vuln), Tshark, OpenSSL, cURL, Ollama IA.
"""
import json, subprocess, sys, shutil, os, re, time, urllib.request, signal, threading
from datetime import datetime

# Asegurar UTF-8 en stdout/stderr SIEMPRE (este módulo usa flechas '→' y emojis en
# los logs). Sin esto, en consolas Windows cp1252 un print lanza UnicodeEncodeError
# y aborta la auditoría. Se aplica al importarse, sea cual sea quien lo invoque.
if sys.platform.startswith('win') or os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ─── RUTAS ABSOLUTAS DE HERRAMIENTAS ─────────────────────────────────────────
# Las rutas de nuclei y sus plantillas se resuelven contra el perfil del usuario
# actual (os.path.expanduser('~')) para que el agente sea portable en cualquier
# equipo Windows sin editar rutas. nmap/tshark/openssl usan sus rutas de
# instalación estándar; ajústalas si las instalaste en otra ubicación.
_USER_HOME = os.path.expanduser("~")
WIN_PATHS = {
    "nmap":    r"C:\Program Files (x86)\Nmap\nmap.exe",
    "tshark":  r"C:\Program Files\Wireshark\tshark.exe",
    "openssl": r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "nuclei":  os.path.join(_USER_HOME, "Documents", "HADES", "nuclei", "nuclei.exe"),
    "ollama":  "http://127.0.0.1:11434/api/generate",
}

# ─── PLANTILLAS NUCLEI ────────────────────────────────────────────────────────
# El agente sólo audita objetivos HTTP/HTTPS, así que únicamente necesita las
# categorías web. El resto de plantillas se descartan del disco para acelerar la
# carga (el set completo de ~13k tardaba >35 s sólo en cargar).
NUCLEI_TEMPLATES_DIR = os.path.join(_USER_HOME, "nuclei-templates")
NUCLEI_CATEGORIES    = ["cves", "exposures", "vulnerabilities", "misconfiguration"]

# Variable global para rastrear el proceso secundario actual
current_process = None

def clean_up_current_process():
    global current_process
    if current_process is not None:
        try:
            # En Windows, para matar un proceso iniciado con shell=True y sus hijos,
            # lo más seguro y rápido es usar taskkill con su PID árbol (/t) y de forma forzada (/f)
            pid = current_process.pid
            subprocess.run(f"taskkill /f /t /pid {pid}", shell=True, capture_output=True)
        except Exception:
            try:
                current_process.kill()
            except Exception:
                pass
        current_process = None

def signal_handler(sig, frame):
    log("\n[EMERGENCIA] Señal de interrupción recibida (Ctrl+C). Finalizando procesos de inmediato...", "WARN")
    clean_up_current_process()
    try:
        subprocess.run("taskkill /f /im nmap.exe /im tshark.exe /im nuclei.exe /im openssl.exe", shell=True, capture_output=True)
    except Exception:
        pass
    sys.exit(1)

# Registrar manejadores de señales
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ─── EJECUCIÓN DE COMANDOS ────────────────────────────────────────────────────
def execute(cmd, timeout=300):
    """
    Ejecuta un comando externo de forma NO BLOQUEANTE en el hilo principal.
    Lee stdout/stderr en threads daemon para que el hilo principal pueda
    responder a señales (Ctrl+C / SIGTERM) cada 100ms como máximo.
    """
    global current_process
    stdout_chunks = []
    stderr_chunks = []

    try:
        current_process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace"
        )

        # Leer stdout y stderr en threads separados para no bloquear el hilo principal
        def _read(pipe, buf):
            try:
                for line in iter(pipe.readline, ''):
                    buf.append(line)
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=_read, args=(current_process.stdout, stdout_chunks), daemon=True)
        t_err = threading.Thread(target=_read, args=(current_process.stderr, stderr_chunks), daemon=True)
        t_out.start()
        t_err.start()

        # ── Polling: el hilo principal espera 100ms entre verificaciones ──
        # Esto permite que Ctrl+C (SIGINT) dispare el signal_handler
        # en ≤ 100ms en lugar de bloquear indefinidamente.
        elapsed = 0.0
        while current_process.poll() is None:
            time.sleep(0.1)
            elapsed += 0.1
            if elapsed >= timeout:
                log(f"[TIMEOUT] Comando excedió {timeout}s. Terminando (se conserva la salida parcial)...", "WARN")
                clean_up_current_process()
                # Conservar lo capturado hasta el corte: si Nuclei/Nmap ya encontró
                # hallazgos, NO deben perderse por agotar el tope de tiempo.
                t_out.join(timeout=3)
                t_err.join(timeout=3)
                partial = "".join(stdout_chunks)
                current_process = None
                return partial + f"\n[TIMEOUT] Comando excedió {timeout}s; resultados PARCIALES: {cmd}"

        # Esperar a que los threads de lectura terminen (máximo 5s)
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        stdout = "".join(stdout_chunks)
        stderr = "".join(stderr_chunks)
        current_process = None
        return stdout + (f"\n[STDERR]: {stderr}" if stderr.strip() else "")

    except (KeyboardInterrupt, SystemExit):
        # Re-lanzar para que el signal_handler global lo capture
        clean_up_current_process()
        raise
    except Exception as e:
        if current_process:
            clean_up_current_process()
        return f"[ERROR]: {str(e)}"

def log(msg, level="*"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

# ─── CLASE PRINCIPAL HadesMCP ─────────────────────────────────────────────────
class HadesMCP:

    # ── Nmap: descubrimiento agresivo por ARP ──────────────────────────────
    def nmap_discovery(self, target="192.168.1.0/24"):
        if not os.path.exists(WIN_PATHS["nmap"]):
            return f"[NMAP] Binario no encontrado en {WIN_PATHS['nmap']}"
        log(f"Nmap ARP discovery → {target}")
        cmd = f'"{WIN_PATHS["nmap"]}" -sn -PR -PE -PS22,80,443,445,8080,8443 {target}'
        return execute(cmd)

    # Perfil EQUILIBRADO: top-1000 puertos (por defecto de Nmap) + versión de servicio
    # + detección de SO, con reintentos y timeout por host para que un host lento o
    # caído no bloquee la auditoría. Las vulnerabilidades web las cubre Nuclei, por lo
    # que se omiten los lentos/inestables scripts NSE '--script vuln'.
    def nmap_scan(self, ip, flags="-T4 -sV -O --osscan-limit --traceroute --max-retries 2 --host-timeout 120s"):
        if not os.path.exists(WIN_PATHS["nmap"]):
            return f"[NMAP] Binario no encontrado en {WIN_PATHS['nmap']}"
        log(f"Nmap deep scan → {ip}")
        cmd = f'"{WIN_PATHS["nmap"]}" {flags} {ip}'
        return execute(cmd, timeout=180)

    # ── Nuclei: escáner de vulnerabilidades web ────────────────────────────
    def nuclei_scan(self, target, categories=None):
        """
        Ejecuta nuclei contra un objetivo HTTP/HTTPS.
        target: IP o URL (ej: http://192.168.1.1 o https://192.168.1.5:8443)
        """
        nuclei_bin = WIN_PATHS["nuclei"]
        if not os.path.exists(nuclei_bin):
            return "[NUCLEI] Binario no encontrado en " + nuclei_bin

        # IMPORTANTE: -t espera RUTAS de plantilla/directorio, NO nombres sueltos.
        # El antiguo '-t cves,exposures,vulnerabilities,misconfiguration' sólo
        # resolvía 2 plantillas (nuclei los tomaba como rutas inexistentes), por lo
        # que el escaneo de vulnerabilidades era prácticamente inútil. Apuntamos a
        # las rutas absolutas de las categorías web.
        cats = categories or NUCLEI_CATEGORIES
        t_args = ""
        for c in cats:
            cdir = os.path.join(NUCLEI_TEMPLATES_DIR, "http", c)
            if os.path.isdir(cdir):
                t_args += f' -t "{cdir}"'
        if not t_args:
            return f"[NUCLEI] Sin directorios de plantillas en {os.path.join(NUCLEI_TEMPLATES_DIR, 'http')}"

        log(f"Nuclei web vuln scan → {target}")
        # -u = URL objetivo, -t = rutas de plantillas, -silent = solo findings,
        # -j = JSON output, -duc = no comprobar/descargar actualizaciones en el escaneo
        cmd = (
            f'"{nuclei_bin}" -u {target}'
            f'{t_args} '
            f'-silent -timeout 8 -retries 1 -j -duc'
        )
        out = execute(cmd, timeout=300)
        return self._parse_nuclei(out, target)

    def _parse_nuclei(self, raw_output, target):
        """Parsea la salida JSON de nuclei en un resumen legible."""
        if not raw_output.strip():
            return f"[NUCLEI] Sin hallazgos en {target}"

        findings = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("[STDERR]") or line.startswith("[ERROR]") or line.startswith("[TIMEOUT]"):
                continue
            try:
                data = json.loads(line)
                sev = data.get("info", {}).get("severity", "unknown").upper()
                name = data.get("info", {}).get("name", "?")
                matched = data.get("matched-at", target)
                cve = data.get("info", {}).get("classification", {}).get("cve-id", [])
                cve_str = f" [{', '.join(cve)}]" if cve else ""
                findings.append(f"  [{sev}] {name}{cve_str} → {matched}")
            except json.JSONDecodeError:
                # Línea no-JSON (puede ser info o advertencia de nuclei)
                if any(k in line.lower() for k in ["found", "critical", "high", "medium", "low"]):
                    findings.append(f"  {line}")

        if not findings:
            return f"[NUCLEI] Sin vulnerabilidades detectadas en {target}"

        return f"[NUCLEI] {len(findings)} hallazgo(s) en {target}:\n" + "\n".join(findings)

    # ── Nuclei: actualizar templates automáticamente ───────────────────────
    def nuclei_update_templates(self, force=False):
        """Las plantillas se instalan/curan UNA sola vez. No se re-descargan en
        cada escaneo: '-update-templates' baja el set completo (~13k) y re-bloatea
        lo que hemos depurado, además de ralentizar el arranque. Sólo descarga si
        faltan por completo (o si se fuerza explícitamente)."""
        http_dir = os.path.join(NUCLEI_TEMPLATES_DIR, "http")
        if not force and os.path.isdir(http_dir):
            log("Plantillas Nuclei ya presentes (omitiendo re-descarga).")
            return "[NUCLEI] Plantillas ya presentes; actualización omitida."
        log("Descargando templates de Nuclei (primera vez)...")
        cmd = f'"{WIN_PATHS["nuclei"]}" -update-templates -silent'
        return execute(cmd, timeout=300)

    # ── Tshark: captura de tráfico ─────────────────────────────────────────
    def tshark_capture(self, interface="Wi-Fi", duration=10, filter_expr=""):
        if not os.path.exists(WIN_PATHS["tshark"]):
            return f"[TSHARK] Binario no encontrado en {WIN_PATHS['tshark']}"
        log(f"Tshark captura → {interface} ({duration}s)")
        filter_part = f'-f "{filter_expr}"' if filter_expr else ""
        tshark_bin = WIN_PATHS["tshark"]
        cmd = (
            f'"{tshark_bin}" -i "{interface}" '
            f'-a duration:{duration} '
            f'{filter_part} '
            f'-T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol'
        )
        return execute(cmd, timeout=duration + 30)

    # ── OpenSSL: auditoría TLS de un host ──────────────────────────────────
    def ssl_audit(self, host, port=443):
        if not os.path.exists(WIN_PATHS["openssl"]):
            return f"[SSL/TLS] OpenSSL no encontrado en {WIN_PATHS['openssl']} — auditoría TLS omitida."
        log(f"OpenSSL TLS audit → {host}:{port}")
        openssl_bin = WIN_PATHS["openssl"]
        cmd = f'echo | "{openssl_bin}" s_client -connect {host}:{port} -showcerts 2>&1'
        return execute(cmd, timeout=20)

    # ── Ollama: análisis IA ────────────────────────────────────────────────
    def _ollama_available(self, timeout=5):
        """Comprobación rápida de que el servidor Ollama responde. Evita lanzar
        reintentos largos (que colgaban la auditoría) contra un servicio caído.
        Cuando Ollama está activo, responde en <100 ms (coste despreciable)."""
        try:
            base = WIN_PATHS["ollama"].rsplit("/api/", 1)[0]
            with urllib.request.urlopen(base + "/api/tags", timeout=timeout) as r:
                r.read()
            return True
        except Exception:
            return False

    def ai_analysis(self, prompt, model="HADES-AUTO:latest", retries=2, timeout=360):
        # El análisis IA DEBE estar presente en el informe. NO usamos pre-chequeo de
        # disponibilidad: cuando Ollama está OCUPADO cargando/generando el modelo,
        # /api/tags tardaba >8s y se marcaba "no disponible" por error, omitiendo la
        # IA. En su lugar llamamos directo: si Ollama está caído, la conexión se
        # rechaza al instante (se captura abajo); si está cargando el modelo (4.7GB),
        # la petición simplemente espera al timeout amplio (300s) y responde.
        # num_predict acota la respuesta. Se subió de 450 → 1536: con 450 tokens los
        # análisis estructurados se cortaban a media frase (la "Interpretación IA" del
        # tráfico quedaba incompleta en la sección 5 — MITIGACIÓN). 1536 da margen para
        # que el modelo CIERRE su respuesta por sí mismo (emite EOS mucho antes en la
        # práctica, así que no penaliza la velocidad real). keep_alive lo mantiene caliente.
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "30m",
            "options": {"num_predict": 1536, "temperature": 0.35}
        }).encode()
        req = urllib.request.Request(
            WIN_PATHS["ollama"], data=payload,
            headers={"Content-Type": "application/json"}
        )
        last = ""
        for i in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as res:
                    txt = json.loads(res.read().decode()).get("response", "").strip()
                    return txt if txt else "[IA] Sin respuesta del modelo."
            except Exception as e:
                last = str(e)
                if i < retries:
                    time.sleep(8)   # esperar a que el modelo termine de cargar / se libere
        return f"[IA] Análisis omitido (el modelo no respondió tras {retries + 1} intentos: {last})."

    def warm_up_model(self, model="HADES-AUTO:latest"):
        """Precarga el modelo en segundo plano (4.7GB tarda en cargar). Así, cuando
        el escaneo llegue a las fases de análisis IA, el modelo ya está caliente y
        no congela el flujo. No bloquea: se ejecuta en un hilo daemon."""
        def _warm():
            try:
                payload = json.dumps({
                    "model": model, "prompt": "ok", "stream": False, "keep_alive": "10m"
                }).encode()
                req = urllib.request.Request(
                    WIN_PATHS["ollama"], data=payload,
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=180).read()
                log("Modelo IA precargado y listo.", "OK")
            except Exception:
                pass
        threading.Thread(target=_warm, daemon=True).start()

    # ── Scan completo de un objetivo: Nmap + Nuclei + TLS + IA ────────────
    def full_audit(self, ip, web_ports=None):
        """
        Auditoría completa de un host:
          1. Nmap profundo (puertos, versiones, scripts de vulnerabilidades)
          2. Nuclei en todos los puertos web detectados
          3. SSL/TLS si hay HTTPS
          4. Análisis IA del informe combinado
        """
        log(f"=== AUDITORÍA COMPLETA: {ip} ===", "HADES")
        report = [f"\n{'='*60}", f"OBJETIVO: {ip}", f"TIMESTAMP: {datetime.now()}", f"{'='*60}"]

        # 1. Nmap
        nmap_out = self.nmap_scan(ip)
        report.append("\n[NMAP]\n" + nmap_out[:3000])

        # 2. Detectar puertos web abiertos del resultado Nmap
        if web_ports is None:
            web_ports = self._detect_web_ports(nmap_out, ip)

        # 3. Nuclei sobre cada puerto web detectado
        nuclei_results = []
        for url in web_ports:
            result = self.nuclei_scan(url)
            nuclei_results.append(result)
            report.append("\n[NUCLEI]\n" + result)

        # 4. SSL/TLS si hay HTTPS
        https_ports = [u for u in web_ports if u.startswith("https://")]
        for url in https_ports:
            host_port = url.replace("https://", "")
            parts = host_port.split(":")
            h = parts[0]
            try:
                p = int(parts[1]) if len(parts) > 1 else 443
            except (ValueError, IndexError):
                p = 443
            ssl_out = self.ssl_audit(h, p)
            report.append("\n[SSL/TLS]\n" + ssl_out[:800])

        # 5. IA analiza todo — estructura alineada al informe ejecutivo ISO 27001
        combined = "\n".join(report)
        ai_prompt = (
            f"Actúa como analista senior de ciberseguridad (pentester + ISO/IEC 27001) de HADES SENTINEL. "
            f"Analiza EXCLUSIVAMENTE los datos reales del host {ip} que se dan abajo (no inventes). Sé TÉCNICO, "
            f"PRECISO y específico: nombra el servicio y su VERSIÓN exacta, cita los CVE concretos que aparezcan "
            f"en los datos, e indica el vector de ataque real. Evita frases genéricas o vagas.\n\n"
            f"Responde SIEMPRE con esta estructura numerada:\n"
            f"1) HALLAZGO: servicios/puertos y vulnerabilidades concretas (con versión y CVE si constan).\n"
            f"2) SEVERIDAD: Crítica/Alta/Media/Baja, justificada según exposición y explotabilidad real.\n"
            f"3) FASE KILL-CHAIN: Reconocimiento, Identificación de vulnerabilidad, Explotación/acceso, "
            f"Backdoor/acceso remoto, Post-explotación/persistencia o Erradicación.\n"
            f"4) IMPACTO DE NEGOCIO: en lenguaje no técnico (robo de información, interrupción de operaciones, "
            f"acceso no autorizado), específico para este activo.\n"
            f"5) MITIGACIÓN: acciones concretas y accionables (configuración, parche, regla de firewall, MFA…), "
            f"priorizadas.\n\n"
            f"DATOS REALES DEL HOST:\n{combined[:4500]}"
        )
        ai_out = self.ai_analysis(ai_prompt)
        report.append("\n[ANÁLISIS IA HADES]\n" + ai_out)

        return "\n".join(report)

    def _detect_web_ports(self, nmap_output, ip):
        """Extrae URLs web (http/https) desde la salida de Nmap."""
        urls = []
        # Buscar puertos abiertos comunes web
        web_port_map = {
            "80": "http", "443": "https", "8080": "http",
            "8443": "https", "8888": "http", "8181": "http",
            "9090": "http", "3000": "http", "4443": "https",
            "5000": "http", "7443": "https",
        }
        for port, scheme in web_port_map.items():
            pattern = rf"{port}/tcp\s+open"
            if re.search(pattern, nmap_output):
                suffix = f":{port}" if port not in ("80", "443") else ""
                urls.append(f"{scheme}://{ip}{suffix}")

        # Si no detectó nada, intenta el estándar
        if not urls:
            if re.search(r"80/tcp\s+open", nmap_output):
                urls.append(f"http://{ip}")
            if re.search(r"443/tcp\s+open", nmap_output):
                urls.append(f"https://{ip}")

        return urls


# ─── PUNTO DE ENTRADA ──────────────────────────────────────────────────────────
def main():
    mcp = HadesMCP()

    if len(sys.argv) > 1:
        mode = sys.argv[1]

        if mode == "surveillance":
            # Descubrimiento y auditoría completa de red
            target = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.0/24"
            res = mcp.nmap_discovery(target)
            ips = re.findall(r"report for (\d+\.\d+\.\d+\.\d+)", res)
            log(f"Dispositivos detectados: {ips}", "HADES")
            for ip in ips:
                report = mcp.full_audit(ip)
                print(report)

        elif mode == "nuclei":
            # Escaneo nuclei directo a una URL
            url = sys.argv[2] if len(sys.argv) > 2 else "http://192.168.1.1"
            print(mcp.nuclei_scan(url))

        elif mode == "nmap":
            # Nmap directo
            ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.1"
            print(mcp.nmap_scan(ip))

        elif mode == "ssl":
            # Auditoría SSL
            host = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.1"
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
            print(mcp.ssl_audit(host, port))

        elif mode == "update-templates":
            print(mcp.nuclei_update_templates())

        else:
            print(f"[HADES] Modo desconocido: {mode}")
            print("Modos: surveillance [red] | nuclei [url] | nmap [ip] | ssl [host] [port] | update-templates")
    else:
        print("[HADES] Uso: python hades_win_master_advanced.py <modo> [target]")
        print("Modos disponibles:")
        print("  surveillance [192.168.1.0/24]  → Escanea toda la red")
        print("  nuclei [http://192.168.1.1]    → Web vuln scan con Nuclei")
        print("  nmap [192.168.1.1]             → Escaneo Nmap profundo")
        print("  ssl [host] [puerto]            → Auditoría TLS")
        print("  update-templates               → Actualiza templates Nuclei")

if __name__ == "__main__":
    main()
