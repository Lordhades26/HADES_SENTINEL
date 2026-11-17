#!/usr/bin/env python3
"""
HADES SECURE DASHBOARD SERVER

Servidor local del agente HADES SENTINEL. Sirve el dashboard tactico y expone
las APIs internas para lanzar/detener escaneos.

Diseno: solo loopback (127.0.0.1:8080). Cero exposicion de red. El dashboard
NO pide inicio de sesion: quien tiene la maquina, tiene el agente.

Eso NO significa que las APIs esten abiertas. Sin sesion de por medio, una web
cualquiera que el usuario visite podria pedirle al navegador que dispare un
escaneo contra http://127.0.0.1:8080 (CSRF), o llegar al puerto por DNS
rebinding. La guardia _request_allowed() cierra ambas puertas exigiendo que la
peticion venga del propio dashboard, sin pedirle nada al usuario.
"""
import os
import sys
import json
import socket
import signal
import atexit
import subprocess
import webbrowser
import threading
import urllib.request
from urllib.parse import urlparse, unquote
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from hades_ai import safe_subprocess_env
from hades_ollama_runtime import ensure_ollama_available
from hades_validation import validate_target
from hades_processes import terminate_process_tree

# Asegurar codificación UTF-8 en Windows para evitar UnicodeEncodeError al imprimir caracteres
if sys.platform.startswith('win') or os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

PORT = 8080
_HERE = os.path.dirname(os.path.abspath(__file__))
MAX_POST_BODY_BYTES = 8 * 1024

# Unicos Host/Origin admitidos. El servidor solo escucha en loopback, pero el
# header Host lo elige el cliente: un dominio del atacante que resuelva a
# 127.0.0.1 (DNS rebinding) llegaria con Host = evil.com. Y el Origin delata a
# cualquier pagina de terceros que intente conducir el agente desde el navegador.
ALLOWED_HOSTS = frozenset({
    f"localhost:{PORT}", f"127.0.0.1:{PORT}", f"[::1]:{PORT}",
})
ALLOWED_ORIGINS = frozenset({
    f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}", f"http://[::1]:{PORT}",
})

# El dashboard sólo necesita estos archivos. No existe un webroot genérico: una
# ruta no listada se trata como inexistente aunque el archivo esté en el repo.
STATIC_ASSETS = {
    "/": ("agente HADES.html", "text/html; charset=utf-8"),
    "/index.html": ("agente HADES.html", "text/html; charset=utf-8"),
    "/agente HADES.html": ("agente HADES.html", "text/html; charset=utf-8"),
    "/assets/logo_hades_sentinel_doc.png": (
        "assets/logo_hades_sentinel_doc.png", "image/png"
    ),
    "/network_map_3d.js": ("network_map_3d.js", "text/javascript; charset=utf-8"),
    "/vendor/hades-graph-bundle.js": (
        "vendor/hades-graph-bundle.js", "text/javascript; charset=utf-8"
    ),
}

# Variables de estado del agente
active_process = None
log_buffer = []

# ---------------------------------------------------------------------------
# Cleanup total al detener el agente. Regla: cuando el server se cierra (Ctrl+C,
# Ctrl+Break, cierre de ventana CMD/PowerShell, SIGTERM, atexit), NO debe quedar
# NADA corriendo — ni el subprocess de escaneo ni sus herramientas hijas.
# Implementación acotada al árbol PID propio: NUNCA mata procesos globales.
# ---------------------------------------------------------------------------
_cleanup_lock = threading.Lock()
_scan_lock = threading.Lock()
_cleanup_done = False

def _kill_active_tree():
    global active_process
    with _scan_lock:
        process = active_process
    if process is None:
        return True
    stopped = terminate_process_tree(process, timeout=5)
    try:
        process.stdout.close()
    except Exception:
        pass
    with _scan_lock:
        if active_process is process and process.poll() is not None:
            active_process = None
    return stopped

def _unload_ollama_models():
    """Descarga TODOS los modelos cargados en Ollama (keep_alive=0). La API
    oficial de Ollama acepta este flag en /api/generate para liberar el modelo
    inmediatamente de RAM/VRAM. Llamado en parada de emergencia para que la
    parada del agente tambien libere los recursos del motor IA. Fail-safe: si
    Ollama no responde, el modelo se descarga eventualmente por TTL natural."""
    # OLLAMA_HOST se define mas abajo en este archivo; si esta funcion corre
    # antes de su definicion, abortamos silencioso.
    try:
        host = OLLAMA_HOST
    except NameError:
        return
    try:
        req = urllib.request.Request(f"{host}/api/ps", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=2.0) as res:
            models = (json.loads(res.read().decode("utf-8")).get("models") or [])
    except Exception:
        return
    for m in models:
        name = m.get("name") or m.get("model")
        if not name:
            continue
        try:
            body = json.dumps({"model": name, "keep_alive": 0}).encode("utf-8")
            req = urllib.request.Request(
                f"{host}/api/generate", data=body, method="POST",
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:
            pass

def _emergency_cleanup(reason="exit"):
    global _cleanup_done
    with _cleanup_lock:
        if _cleanup_done:
            return
        _cleanup_done = True
    try:
        sys.stderr.write(f"\n[HADES] Cleanup ({reason}) — terminando subprocesos...\n")
        sys.stderr.flush()
    except Exception:
        pass
    _kill_active_tree()

def _signal_handler(signum, _frame):
    _emergency_cleanup(f"signal {signum}")
    code = 130 if signum == signal.SIGINT else 0
    sys.exit(code)

atexit.register(_emergency_cleanup, "atexit")
try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _signal_handler)  # Ctrl+Break en Windows
except Exception:
    pass

# Windows-only: capturar cierre de ventana de consola (CTRL_CLOSE_EVENT). Sin
# esto, cerrar la ventana del .bat mata Python inmediatamente sin disparar
# atexit ni signal handlers, dejando subprocesos huérfanos. SetConsoleCtrlHandler
# da ~5 s antes del kill forzoso del SO — suficiente para taskkill+revoke.
if os.name == "nt":
    try:
        import ctypes
        from ctypes import wintypes
        _CTRL_HANDLER = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        def _win_console_handler(ctrl_type):
            # 0=C 1=BREAK 2=CLOSE 5=LOGOFF 6=SHUTDOWN
            _emergency_cleanup(f"console event {ctrl_type}")
            return False  # dejar que el flujo normal del SO también corra
        _win_console_handler_ref = _CTRL_HANDLER(_win_console_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_console_handler_ref, True)
    except Exception:
        pass

system_metrics = {
    "cpu": 0.0,
    "ram": 0.0,
    "gpu": 0.0,
    "disk": 0.0,
    "temp": 0.0,
    "fan": 0.0
}

# Estado REAL de Ollama (no simulado). Lo actualiza monitor_ollama() consultando
# directamente la API local de Ollama (http://127.0.0.1:11434). El frontend lo
# consume vía GET /api/ollama. Los campos tokens_per_second y total_duration_ms
# vienen del archivo .ollama_last_metrics.json que escribe hades_local.py tras
# cada llamada real a /api/generate.
def _normalize_ollama_host(raw):
    # Ollama's propia convención para OLLAMA_HOST es "host" o "host:port" (sin
    # esquema). urllib exige un URL completo, así que normalizamos: añadimos
    # http:// si falta, y :11434 si no se especificó puerto. Acepta también un
    # URL completo ya formado.
    s = (raw or "").strip()
    if not s:
        return "http://127.0.0.1:11434"
    if "://" not in s:
        s = "http://" + s
    try:
        u = urlparse(s)
        host = u.hostname or "127.0.0.1"
        # 0.0.0.0 es una dirección de bind del lado servidor; como cliente no es
        # ruteable en Windows. La convertimos al loopback.
        if host == "0.0.0.0":
            host = "127.0.0.1"
        port = u.port or 11434
        scheme = u.scheme or "http"
        return f"{scheme}://{host}:{port}"
    except Exception:
        return "http://127.0.0.1:11434"

OLLAMA_HOST = _normalize_ollama_host(os.environ.get("OLLAMA_HOST"))
_OLLAMA_METRICS_FILE = os.path.join(_HERE, ".ollama_last_metrics.json")
ollama_metrics = {
    "connected": False,
    "version": None,
    "model_name": None,
    "vram_mb": 0,
    "size_mb": 0,
    "expires_in_seconds": 0,
    "loaded_models": 0,
    "tokens_per_second": 0.0,
    "total_duration_ms": 0,
    "last_metric_age_seconds": None,
    "error": None,
    "runtime_state": "not_checked",
    "runtime_detail": "Runtime de Ollama aún no evaluado.",
}


def _initialize_ollama_runtime(ensure_runtime=ensure_ollama_available):
    """Evalúa Ollama una vez sin convertir su disponibilidad en requisito."""
    status = ensure_runtime()
    ollama_metrics["runtime_state"] = status.state
    ollama_metrics["runtime_detail"] = status.detail
    return status

def _http_get_json(url, timeout=2.5):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read().decode("utf-8"))

def monitor_ollama():
    """Polling cada 3 s al API local de Ollama para reflejar el estado REAL del
    motor de IA en el dashboard. Si el host no responde marca connected=False y
    los demás campos se ponen a cero. Es defensivo: cualquier excepción se
    encapsula en ollama_metrics['error']."""
    global ollama_metrics
    import time
    while True:
        snap = {
            "connected": False,
            "version": None,
            "model_name": None,
            "vram_mb": 0,
            "size_mb": 0,
            "expires_in_seconds": 0,
            "loaded_models": 0,
            "tokens_per_second": 0.0,
            "total_duration_ms": 0,
            "last_metric_age_seconds": None,
            "error": None,
            "runtime_state": ollama_metrics.get(
                "runtime_state", "not_checked"
            ),
            "runtime_detail": ollama_metrics.get(
                "runtime_detail", "Runtime de Ollama aún no evaluado."
            ),
        }
        try:
            ver = _http_get_json(f"{OLLAMA_HOST}/api/version", timeout=2.0)
            snap["connected"] = True
            snap["version"] = ver.get("version")
        except Exception as e:
            snap["error"] = f"version: {e.__class__.__name__}"

        if snap["connected"]:
            try:
                ps = _http_get_json(f"{OLLAMA_HOST}/api/ps", timeout=2.5)
                models = ps.get("models", []) or []
                snap["loaded_models"] = len(models)
                if models:
                    # Tomar el primero (modelo activo). Sumar VRAM total y tamaño.
                    primary = models[0]
                    snap["model_name"] = primary.get("name") or primary.get("model")
                    snap["vram_mb"] = int(sum(m.get("size_vram", 0) for m in models) / (1024 * 1024))
                    snap["size_mb"] = int(sum(m.get("size", 0) for m in models) / (1024 * 1024))
                    expires_at = primary.get("expires_at")
                    if expires_at:
                        # Ollama emite ISO 8601 con offset, ej:
                        #   "2026-06-04T15:50:54.3154521-03:00"  (hora local)
                        #   "2026-06-04T18:50:54.3154521Z"        (UTC)
                        # Antes haciamos rstrip('Z') + replace(tzinfo=UTC), lo que
                        # convertia HORA LOCAL a UTC erroneamente y siempre daba
                        # delta negativo -> Keep-Alive = 0. fromisoformat de Python
                        # 3.11+ entiende el offset directamente; solo hay que recortar
                        # microsegundos de 7+ digitos (la lib solo acepta 6).
                        try:
                            import re
                            from datetime import datetime, timezone
                            s = expires_at.replace("Z", "+00:00")
                            s = re.sub(r"(\.\d{6})\d+", r"\1", s)
                            dt = datetime.fromisoformat(s)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            delta = (dt - datetime.now(timezone.utc)).total_seconds()
                            snap["expires_in_seconds"] = max(0, int(delta))
                        except Exception:
                            snap["expires_in_seconds"] = 0
            except Exception as e:
                snap["error"] = f"ps: {e.__class__.__name__}"

        # Inyectar métricas escritas por hades_local.py tras cada inferencia real
        try:
            if os.path.exists(_OLLAMA_METRICS_FILE):
                with open(_OLLAMA_METRICS_FILE, "r", encoding="utf-8") as f:
                    last = json.load(f)
                snap["tokens_per_second"] = float(last.get("tokens_per_second", 0.0))
                snap["total_duration_ms"] = int(last.get("total_duration_ms", 0))
                ts = float(last.get("timestamp", 0.0))
                if ts > 0:
                    snap["last_metric_age_seconds"] = max(0, int(time.time() - ts))
        except Exception:
            pass

        ollama_metrics = snap
        time.sleep(3)

def monitor_system_resources():
    """CPU/RAM/disco vía psutil (rápido, cada ciclo). GPU/temp/ventilador vía
    PowerShell sólo cada ~30 s (son caros y cambian lento); el resto del tiempo se
    reutiliza el último valor o se estima desde la CPU. Así se evita la tormenta de
    procesos PowerShell que saturaba el servidor y causaba timeouts."""
    global system_metrics
    import time
    try:
        import psutil
        psutil.cpu_percent()
    except Exception:
        psutil = None

    heavy = {"gpu": 0.0, "temp": 0.0, "fan": 0.0}  # caché de métricas pesadas
    loop = 0
    while True:
        cpu = ram = disk = 0.0
        try:
            if psutil:
                cpu = psutil.cpu_percent(interval=None)
                ram = psutil.virtual_memory().percent
                disk = psutil.disk_usage('C:\\').percent
        except Exception:
            pass

        # GPU/temp/ventilador: PowerShell sólo cada 15 ciclos (~30 s)
        if loop % 15 == 0:
            try:
                cmd_gpu = "powershell -NoProfile -Command \"$g = Get-Counter '\\GPU Engine(*)\\Utilization Percentage' -ErrorAction SilentlyContinue; if ($g) { ($g.CounterSamples | Measure-Object -Property CookedValue -Max).Maximum } else { 0 }\""
                val = subprocess.run(cmd_gpu, shell=True, capture_output=True, text=True, timeout=8).stdout.strip()
                if val:
                    heavy["gpu"] = round(float(val.replace(',', '.')), 1)
            except Exception:
                pass
            try:
                cmd_temp = "powershell -NoProfile -Command \"$t = Get-CimInstance -Namespace root/wmi -ClassName MsAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue; if ($t) { ($t.CurrentTemperature - 273.15) / 10 } else { 0 }\""
                vt = subprocess.run(cmd_temp, shell=True, capture_output=True, text=True, timeout=8).stdout.strip()
                heavy["temp"] = round(float(vt.replace(',', '.')), 1) if vt else 0.0
            except Exception:
                heavy["temp"] = 0.0

        # Estimaciones cuando no hay lectura real (temp desde CPU, ventilador desde temp)
        temp = heavy["temp"] if heavy["temp"] > 0 else round(45.0 + (cpu * 0.25), 1)
        fan = round(min(3500, 1200 + max(0, (temp - 40) * 80)))

        system_metrics = {"cpu": cpu, "ram": ram, "gpu": heavy["gpu"],
                          "disk": disk, "temp": temp, "fan": fan}
        loop += 1
        time.sleep(2)

_background_monitors_started = False


def _start_background_monitors(thread_factory=threading.Thread):
    """Inicia monitores una sola vez y únicamente durante el arranque real."""
    global _background_monitors_started
    if _background_monitors_started:
        return
    _background_monitors_started = True
    for target in (monitor_system_resources, monitor_ollama):
        thread_factory(target=target, daemon=True).start()

def add_log(msg):
    log_buffer.append(msg)
    print(f"[SERVER] {msg}")


_rdns_cache = {}        # ip -> hostname ("" si no tiene PTR)
_rdns_inflight = set()


def _sanitize_ptr(host):
    """El PTR lo controla el dueño de la IP remota: sólo se acepta un hostname
    RFC 1123 válido. Cualquier otra cosa (HTML, comillas, espacios) se descarta
    para que nunca llegue a la etiqueta HTML del mapa (XSS → POST /api/scan)."""
    from hades_validation import _is_valid_hostname
    host = (host or "").strip().rstrip(".")
    return host if host and _is_valid_hostname(host) else ""


def _queue_rdns(ip):
    """Resuelve el DNS inverso (PTR) de una IP en segundo plano y lo cachea.
    No bloquea /api/graph: el hostname aparece en el siguiente ciclo de polling."""
    if ip in _rdns_cache or ip in _rdns_inflight:
        return
    _rdns_inflight.add(ip)

    def _resolve():
        host = ""
        try:
            host = _sanitize_ptr(socket.gethostbyaddr(ip)[0])
        except Exception:
            host = ""
        _rdns_cache[ip] = host
        _rdns_inflight.discard(ip)

    threading.Thread(target=_resolve, daemon=True).start()


def _parse_traffic(summary):
    """Extrae IPs externas y conexiones host→destino del resumen de tráfico Tshark."""
    import re
    externals, connections = [], []
    if not summary:
        return externals, connections
    m = re.search(r"IPs externas detectadas:(.*?)(?:\n\s*Actividad|\Z)", summary, re.DOTALL)
    if m:
        # Extraer TODAS las IPs del bloque (incluye líneas con varias IPs separadas
        # por comas). Sólo se descarta 0.0.0.0; el resto (incl. broadcast/multicast
        # que el escaneo contó como externas) se muestran para que el mapa las liste
        # todas, igual que el informe.
        for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", m.group(1)):
            if ip and ip != "0.0.0.0":
                externals.append(ip)
    for line in summary.splitlines():
        hm = re.match(r"\s*\[([\d.]+)\]:\s*(.+)", line)
        if hm and "sin tráfico" not in hm.group(2).lower():
            src = hm.group(1)
            for conn in re.finditer(r"(\w+):(\S+)\s*→\s*([\d.]+)\s*\((\d+)x\)", hm.group(2)):
                connections.append({"src": src, "proto": conn.group(1), "port": conn.group(2),
                                    "dst": conn.group(3), "count": int(conn.group(4))})
    return list(dict.fromkeys(externals)), connections


def build_graph_data():
    """Lee el INFORME_MAESTRO.md más reciente y devuelve datos estructurados
    (hosts con SO, MAC, fabricante, puertos, tipo, riesgo, latencia, traceroute,
    + IPs externas y conexiones del tráfico) para el mapa de red 3D."""
    import re
    from collections import Counter
    result = {"status": "idle", "subnet": "", "generated": "", "router_ip": "",
              "hosts": [], "externals": [], "connections": [], "traffic": {}, "stats": {}}
    informes = os.path.join(_HERE, "informes")
    if not os.path.isdir(informes):
        return result
    candidates = []
    for name in os.listdir(informes):
        f = os.path.join(informes, name, "INFORME_MAESTRO.md")
        if os.path.isfile(f):
            candidates.append((os.path.getmtime(f), f))
    if not candidates:
        return result
    candidates.sort(reverse=True)
    master = candidates[0][1]
    try:
        from hades_report_docx import parse_master_report
        with open(master, "r", encoding="utf-8") as fh:
            data = parse_master_report(fh.read())
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result

    hosts = data.get("hosts", [])
    audited = {h["ip"] for h in hosts}
    # Incluir IPs descubiertas en FASE 1 aunque aún no estén auditadas (para que
    # el mapa muestre la red en cuanto se descubre, sin esperar a la FASE 4).
    for ip in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", data.get("ips_raw", "")):
        if ip not in audited:
            hosts.append({"ip": ip, "status": "descubierto",
                          "device_type": "Router / Gateway" if ip.endswith(".1") else "Descubierto (sin auditar)",
                          "risk": "INFORMATIVO", "ports": [], "os": "", "mac": "", "vendor": "",
                          "cves": [], "nuclei": [], "latency": "", "traceroute": [], "ai": ""})
            audited.add(ip)

    router_ip = next((h["ip"] for h in hosts if h["ip"].endswith(".1")), "")
    externals, connections = _parse_traffic(data.get("traffic_summary", ""))

    # DNS inverso (PTR) de cada IP externa → dominio/host al que pertenece
    hostnames = {}
    for ip in set(externals) | {cn["dst"] for cn in connections}:
        if ip in _rdns_cache:
            hostnames[ip] = _rdns_cache[ip]
        else:
            _queue_rdns(ip)        # resuelve en segundo plano; aparece en el próximo poll
            hostnames[ip] = ""

    c = Counter(h["risk"] for h in hosts)
    result.update({
        "status": "ok",
        "subnet": data.get("subnet", ""),
        "generated": data.get("date", ""),
        "router_ip": router_ip,
        "hosts": hosts,
        "externals": externals,
        "connections": connections,
        "hostnames": hostnames,
        "traffic": {"summary": data.get("traffic_summary", "")},
        "stats": {
            "total": len(hosts),
            "activos": sum(1 for h in hosts if h["status"].startswith("activo")),
            "externos": len(externals),
            "puertos_abiertos": sum(len(h["ports"]) for h in hosts),
            "riesgo": {k: c.get(k, 0) for k in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "NO EVALUADO", "INFORMATIVO"]},
        },
    })
    return result


def _resolve_static_asset(request_path):
    """Resuelve una ruta pública exacta sin atravesar symlinks ni el webroot.

    Devuelve ``(ruta_absoluta, content_type)`` sólo para archivos de
    ``STATIC_ASSETS`` que existan como archivos regulares dentro de ``_HERE``.
    """
    try:
        public_path = unquote(request_path)
    except (TypeError, ValueError):
        return None
    if "\x00" in public_path:
        return None
    entry = STATIC_ASSETS.get(public_path)
    if entry is None:
        return None

    relative_path, content_type = entry
    candidate = os.path.abspath(os.path.join(_HERE, relative_path))
    try:
        if os.path.commonpath((_HERE, candidate)) != _HERE:
            return None
    except ValueError:
        return None

    # ``realpath`` por sí solo seguiría el enlace. Se rechaza cualquier enlace
    # en la cadena completa, incluido el propio asset.
    cursor = _HERE
    for component in relative_path.replace("\\", "/").split("/"):
        cursor = os.path.join(cursor, component)
        if os.path.islink(cursor):
            return None
    if os.path.realpath(candidate) != candidate or not os.path.isfile(candidate):
        return None
    return candidate, content_type


def _launch_scan_process(arguments, **kwargs):
    """Punto único de creación del agente, inyectable en pruebas."""
    return subprocess.Popen(arguments, **kwargs)


def _build_scan_env(source=None):
    """Entorno mínimo del escaneo; nunca hereda tokens ni API keys."""
    return safe_subprocess_env(source)


class SecureHadesHandler(SimpleHTTPRequestHandler):
    # HTTP/1.1 con keep-alive: el navegador reutiliza unas pocas conexiones en lugar
    # de abrir cientos de conexiones cortas (una por cada poll), que saturaban el
    # servidor en loopback de Windows y lo dejaban sin responder. Requiere enviar
    # Content-Length en TODAS las respuestas (ver _send_json / _send_bytes).
    protocol_version = "HTTP/1.1"
    timeout = 30

    def __init__(self, *args, **kwargs):
        # Establecer la carpeta raíz para servir archivos estáticos
        super().__init__(*args, directory=_HERE, **kwargs)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # CORS: sin Access-Control-Allow-Origin = same-origin only. El dashboard
        # vive en el mismo origen (loopback :8080), no necesita CORS abierto.
        # Abrirlo a "*" dejaria que cualquier web del navegador leyera las
        # respuestas de las APIs del agente.
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _send_bytes(self, body, content_type, code=200):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def log_message(self, format, *args):
        # Silenciar logs estándar en terminal para evitar ruido
        pass

    def end_headers(self):
        # Sin caché: el dashboard es local y evoluciona; así el navegador siempre
        # recibe la versión actual de los .js/.html sin necesidad de recarga forzada.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        # Anti-clickjacking: ninguna página puede enmarcar el dashboard para
        # inducir clics sobre «Escanear»/«Detener». No limita scripts.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def _request_allowed(self):
        """Guardia de mismo origen. Sustituye al login WebAuthn: no le pide nada
        al usuario, solo comprueba que la peticion nace del propio dashboard.

        - Host debe ser loopback: corta el DNS rebinding, donde evil.com resuelve
          a 127.0.0.1 y el navegador entrega el puerto al atacante.
        - Origin, si viene, debe ser el dashboard: corta el CSRF. Los navegadores
          mandan Origin en todo POST (fetch, XHR y formularios), asi que una web
          de terceros se delata sola.
        - Origin ausente = navegacion directa o herramienta local (curl, scripts
          del propio usuario). Se permite: ya esta dentro de la maquina."""
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in ALLOWED_ORIGINS

    def _serve_static_asset(self, path):
        resolved = _resolve_static_asset(path)
        if resolved is None:
            self.send_error(404, "Not Found")
            return
        asset_path, content_type = resolved
        try:
            with open(asset_path, "rb") as asset:
                body = asset.read()
        except (OSError, ValueError):
            self.send_error(404, "Not Found")
            return
        self._send_bytes(body, content_type)

    def _handle_get_or_head(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # La guardia se aplica antes de decidir la ruta. Esto incluye estáticos,
        # GET y HEAD, cerrando DNS rebinding sobre todo el servidor.
        if not self._request_allowed():
            self.send_error(403, "Forbidden: Cross-origin request")
            return

        # 1. API: Obtener logs en tiempo real
        if path == "/api/logs":
            global log_buffer
            self._send_json({"logs": log_buffer})
            if self.command != "HEAD":
                log_buffer = []  # HEAD nunca debe tener efectos laterales
            return

        # 2. API: Obtener estado
        if path == "/api/status":
            with _scan_lock:
                process = active_process
            is_running = process is not None and process.poll() is None
            self._send_json({"status": "running" if is_running else "idle", "port": PORT})
            return

        # 2.5 API: Obtener recursos del sistema
        if path == "/api/sysinfo":
            self._send_json(system_metrics)
            return

        # 2.55 API: Estado REAL de Ollama (modelo cargado, VRAM, tokens/s)
        if path == "/api/ollama":
            self._send_json(ollama_metrics)
            return

        # 2.6 API: Datos estructurados de la red para el mapa 3D
        if path == "/api/graph":
            try:
                graph = build_graph_data()
            except Exception as e:
                graph = {"status": "error", "error": str(e), "hosts": []}
            self._send_json(graph)
            return

        self._serve_static_asset(path)

    def do_GET(self):
        self._handle_get_or_head()

    def do_HEAD(self):
        self._handle_get_or_head()

    def _read_json_body(self):
        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return None, 415, "Content-Type debe ser application/json."

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return None, 411, "Content-Length es obligatorio."
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            return None, 400, "Content-Length inválido."
        if length < 0:
            return None, 400, "Content-Length inválido."
        if length > MAX_POST_BODY_BYTES:
            return None, 413, "El cuerpo supera el límite de 8 KiB."

        body = self.rfile.read(length)
        if len(body) != length:
            return None, 400, "Cuerpo HTTP incompleto."
        try:
            params = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, 400, "JSON inválido."
        return params, None, None

    @staticmethod
    def _validate_scan_params(params):
        if not isinstance(params, dict) or set(params) != {"target", "duration"}:
            return None, "El JSON debe contener únicamente target y duration."
        target = params["target"]
        duration = params["duration"]
        if not isinstance(target, str) or validate_target(target) is None:
            return None, "target debe ser un objetivo de red válido."
        if isinstance(duration, bool) or not isinstance(duration, int):
            return None, "duration debe ser un entero."
        if not 5 <= duration <= 300:
            return None, "duration debe estar entre 5 y 300 segundos."
        return (target, duration), None

    def do_POST(self):
        global active_process, log_buffer
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if not self._request_allowed():
            self.send_error(403, "Forbidden: Cross-origin request")
            return

        if path not in {"/api/scan", "/api/stop"}:
            self.send_error(404, "Not Found")
            return

        # 1. API para lanzar el agente
        if path == "/api/scan":
            params, error_code, error_message = self._read_json_body()
            if error_code is not None:
                self._send_json({"error": error_message}, code=error_code)
                return
            validated, error_message = self._validate_scan_params(params)
            if error_message is not None:
                self._send_json({"error": error_message}, code=400)
                return
            target, duration_value = validated
            duration = str(duration_value)

            script_path = os.path.join(_HERE, "hades_surveillance_advanced.py")
            env = _build_scan_env()

            # Popen y publicación de active_process son una única sección
            # crítica. Una segunda petición no puede observar un estado IDLE
            # entre la comprobación y el arranque.
            with _scan_lock:
                if active_process is not None and active_process.poll() is None:
                    self._send_json(
                        {"error": "El agente ya se encuentra activo."}, code=400
                    )
                    return
                try:
                    process = _launch_scan_process(
                        [sys.executable, script_path, target, duration],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        bufsize=1,
                        cwd=_HERE,
                        env=env,
                    )
                except (OSError, subprocess.SubprocessError) as exc:
                    add_log(f"[ERROR] No se pudo iniciar el agente: {exc}")
                    self._send_json(
                        {"error": "No se pudo iniciar el agente."}, code=500
                    )
                    return
                active_process = process

            add_log(f"Lanzando HADES en rango '{target}' con captura de {duration}s...")

            def monitor_subprocess(process):
                global active_process
                # Leer la salida en tiempo real de forma segura
                # Si el proceso es terminado forzosamente desde /api/stop,
                # el stream se cierra y readline lanza ValueError/OSError.
                # Capturamos estas excepciones para no colapsar el hilo.
                try:
                    for line in iter(process.stdout.readline, ""):
                        if line:
                            add_log(line.strip())
                except (ValueError, OSError):
                    # El stream fue cerrado externamente (parada de emergencia)
                    pass
                finally:
                    try:
                        process.stdout.close()
                    except Exception:
                        pass
                    try:
                        process.wait(timeout=5)
                    except (subprocess.TimeoutExpired, TimeoutError):
                        terminate_process_tree(process, timeout=3)
                    exit_code = process.returncode
                    add_log(f"--- AGENTE FINALIZADO (Codigo de salida: {exit_code}) ---")
                    with _scan_lock:
                        if active_process is process and process.poll() is not None:
                            active_process = None

            threading.Thread(
                target=monitor_subprocess, args=(process,), daemon=True
            ).start()

            self._send_json({"message": "Escaneo iniciado correctamente."})
            return

        # 2. API para parada forzada de emergencia — TERMINACIÓN INMEDIATA
        if path == "/api/stop":
            params, error_code, error_message = self._read_json_body()
            if error_code is not None:
                self._send_json({"error": error_message}, code=error_code)
                return
            if params != {}:
                self._send_json(
                    {"error": "La parada sólo admite un objeto JSON vacío."},
                    code=400,
                )
                return

            add_log("[EMERGENCIA] ⚡ PARADA DE EMERGENCIA ACTIVADA — Terminando todos los procesos...")

            with _scan_lock:
                process = active_process
            if process is not None:
                pid_msg = process.pid
                add_log(f"[EMERGENCIA] taskkill /f /t sobre PID {pid_msg} y árbol de hijos...")
            else:
                add_log("[INFO] Sin proceso de agente activo registrado — limpieza preventiva.")

            tree_stopped = _kill_active_tree()

            # Liberar tambien el modelo IA: si el agente se detiene, no debe
            # quedar el modelo ocupando RAM/VRAM. Ollama acepta keep_alive=0
            # como senial de descarga inmediata.
            add_log("[EMERGENCIA] Solicitando descarga de modelos Ollama (keep_alive=0)...")
            _unload_ollama_models()
            # Reset inmediato del snapshot para que el dashboard refleje
            # "sin modelo" sin esperar al siguiente ciclo del monitor.
            global ollama_metrics
            ollama_metrics = {
                "connected": ollama_metrics.get("connected", False),
                "version": ollama_metrics.get("version"),
                "model_name": None, "vram_mb": 0, "size_mb": 0,
                "expires_in_seconds": 0, "loaded_models": 0,
                "tokens_per_second": 0.0, "total_duration_ms": 0,
                "last_metric_age_seconds": None, "error": None,
            }

            if not tree_stopped:
                add_log(
                    "[ERROR] No se pudo confirmar la terminación completa del "
                    "árbol del agente."
                )
                self._send_json(
                    {
                        "error": "No se confirmó la terminación del árbol del agente.",
                        "reset": False,
                    },
                    code=500,
                )
                return

            add_log("[OK] ✅ Subprocesos terminados, modelo Ollama liberado. Estado del servidor reseteado.")
            log_buffer = ["[RESET] Agente detenido y estado reiniciado a CERO. Listo para una nueva auditoría."]

            self._send_json({
                "message": "Agente detenido. Modelo IA liberado. Estado reiniciado a CERO.",
                "reset": True
            })
            return

class HadesHTTPServer(ThreadingHTTPServer):
    # Cola de conexiones grande (por defecto 5): el navegador abre muchas conexiones
    # concurrentes (polling de /api/logs, /api/status, /api/sysinfo, /api/graph + la
    # librería de 1.3MB). Con backlog 5 se desbordaba y Windows descartaba los SYN
    # → ERR_CONNECTION_TIMED_OUT. 128 absorbe las ráfagas del dashboard.
    request_queue_size = 128
    daemon_threads = True


def start_server():
    runtime_status = _initialize_ollama_runtime()
    _start_background_monitors()
    server = HadesHTTPServer(('127.0.0.1', PORT), SecureHadesHandler)
    server.daemon_threads = True
    url = f"http://localhost:{PORT}/"

    print("=" * 70)
    print("   HADES SECURITY COMMAND CENTER SERVER ACTIVO")
    print(f"   Puerto: {PORT}")
    print(f"   Acceso: directo, sin login (guardia de mismo origen en las APIs)")
    print(f"   Ollama: {runtime_status.state} — {runtime_status.detail}")
    print(f"   Abriendo navegador en: {url}")
    print("=" * 70)

    webbrowser.open(url)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[HADES] Ctrl+C recibido — cerrando server y limpiando subprocesos...")
        _emergency_cleanup("KeyboardInterrupt")
        try:
            server.server_close()
        except Exception:
            pass
        print("[HADES] Cierre limpio completado.")

if __name__ == "__main__":
    start_server()
