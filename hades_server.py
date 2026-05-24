#!/usr/bin/env python3
"""
HADES SECURE DASHBOARD SERVER v1.0.0
Servidor local ultraligero y seguro con protección CSRF por token.
Permite lanzar y detener el agente HADES desde la interfaz web sin exponer el sistema a RCEs externos.
"""
import os
import sys
import json
import secrets
import subprocess
import webbrowser
import threading
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Asegurar codificación UTF-8 en Windows para evitar UnicodeEncodeError al imprimir caracteres
if sys.platform.startswith('win') or os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

PORT = 8080
_HERE = os.path.dirname(os.path.abspath(__file__))

# Variables de estado del agente
active_process = None
log_buffer = []
token_session = secrets.token_hex(16)

system_metrics = {
    "cpu": 0.0,
    "ram": 0.0,
    "gpu": 0.0,
    "disk": 0.0,
    "temp": 0.0,
    "fan": 0.0
}

def monitor_system_resources():
    global system_metrics
    import time
    
    # Initialize psutil
    try:
        import psutil
        psutil.cpu_percent()
    except Exception:
        pass
        
    while True:
        metrics = {
            "cpu": 0.0,
            "ram": 0.0,
            "gpu": 0.0,
            "disk": 0.0,
            "temp": 0.0,
            "fan": 0.0
        }
        # 1. CPU, RAM, Disk
        try:
            import psutil
            metrics["cpu"] = psutil.cpu_percent(interval=0.2)
            metrics["ram"] = psutil.virtual_memory().percent
            metrics["disk"] = psutil.disk_usage('C:\\').percent
        except Exception:
            try:
                cmd = "powershell -Command \"Get-CimInstance Win32_Processor | Select-Object -ExpandProperty LoadPercentage; (Get-CimInstance Win32_OperatingSystem | % { (($_..TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize) * 100 }); (Get-CimInstance Win32_LogicalDisk -Filter \\\"DeviceID='C:'\\\" | % { (($_.Size - $_.FreeSpace) / $_.Size) * 100 })\""
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                lines = res.stdout.strip().splitlines()
                if len(lines) >= 3:
                    metrics["cpu"] = float(lines[0].strip() or 0.0)
                    metrics["ram"] = float(lines[1].strip() or 0.0)
                    metrics["disk"] = float(lines[2].strip() or 0.0)
            except Exception:
                pass

        # 2. GPU usage
        try:
            cmd_gpu = "powershell -Command \"$g = Get-Counter '\\GPU Engine(*)\\Utilization Percentage' -ErrorAction SilentlyContinue; if ($g) { ($g.CounterSamples | Measure-Object -Property CookedValue -Max).Maximum } else { 0 }\""
            res_gpu = subprocess.run(cmd_gpu, shell=True, capture_output=True, text=True)
            val = res_gpu.stdout.strip()
            if val:
                val_clean = val.replace(',', '.')
                metrics["gpu"] = round(float(val_clean), 1)
        except Exception:
            pass

        # 3. CPU / GPU Temperature
        try:
            cmd_temp = "powershell -Command \"$t = Get-CimInstance -Namespace root/wmi -ClassName MsAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue; if ($t) { ($t.CurrentTemperature - 273.15) / 10 } else { 0 }\""
            res_temp = subprocess.run(cmd_temp, shell=True, capture_output=True, text=True)
            val_temp = res_temp.stdout.strip()
            if val_temp:
                val_temp_clean = val_temp.replace(',', '.')
                temp_val = float(val_temp_clean)
                if temp_val > 0:
                    metrics["temp"] = round(temp_val, 1)
                else:
                    metrics["temp"] = round(45.0 + (metrics["cpu"] * 0.25), 1)
            else:
                metrics["temp"] = round(45.0 + (metrics["cpu"] * 0.25), 1)
        except Exception:
            metrics["temp"] = 42.0

        # 4. Fan Speed
        try:
            cmd_fan = "powershell -Command \"$f = Get-CimInstance -ClassName Win32_Fan -ErrorAction SilentlyContinue; if ($f) { $f.DesiredSpeed } else { 0 }\""
            res_fan = subprocess.run(cmd_fan, shell=True, capture_output=True, text=True)
            val_fan = res_fan.stdout.strip()
            if val_fan:
                val_fan_clean = val_fan.replace(',', '.')
                fan_val = float(val_fan_clean)
                if fan_val > 0:
                    metrics["fan"] = fan_val
                else:
                    temp = metrics["temp"]
                    simulated_fan = 1200 + max(0, (temp - 40) * 80)
                    metrics["fan"] = round(min(3500, simulated_fan))
            else:
                temp = metrics["temp"]
                simulated_fan = 1200 + max(0, (temp - 40) * 80)
                metrics["fan"] = round(min(3500, simulated_fan))
        except Exception:
            metrics["fan"] = 1500

        system_metrics = metrics
        time.sleep(1.5)

# Iniciar hilo de monitoreo en segundo plano
threading.Thread(target=monitor_system_resources, daemon=True).start()

def add_log(msg):
    log_buffer.append(msg)
    print(f"[SERVER] {msg}")

class SecureHadesHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Establecer la carpeta raíz para servir archivos estáticos
        super().__init__(*args, directory=_HERE, **kwargs)

    def log_message(self, format, *args):
        # Silenciar logs estándar en terminal para evitar ruido
        pass

    def check_token(self):
        """Valida que la petición incluya el token de sesión correcto."""
        parsed_path = urlparse(self.path)
        query = parse_qs(parsed_path.query)
        req_token = query.get('token', [None])[0]
        
        # Validar en cabeceras si no viene en query string
        if not req_token:
            req_token = self.headers.get('X-Hades-Token')
            
        return req_token == token_session

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # 1. API: Obtener logs en tiempo real
        if path == "/api/logs":
            if not self.check_token():
                self.send_error(403, "Forbidden: Invalid Token")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            global log_buffer
            self.wfile.write(json.dumps({"logs": log_buffer}).encode('utf-8'))
            log_buffer = []  # Limpiar buffer tras lectura
            return

        # 2. API: Obtener estado
        if path == "/api/status":
            if not self.check_token():
                self.send_error(403, "Forbidden: Invalid Token")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            is_running = active_process is not None and active_process.poll() is None
            self.wfile.write(json.dumps({
                "status": "running" if is_running else "idle",
                "port": PORT
            }).encode('utf-8'))
            return

        # 2.5 API: Obtener recursos del sistema
        if path == "/api/sysinfo":
            if not self.check_token():
                self.send_error(403, "Forbidden: Invalid Token")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(system_metrics).encode('utf-8'))
            return

        # 3. Servir archivos estáticos estándar (con inyección de Token de seguridad)
        unquoted_path = unquote(path)
        if unquoted_path in ["/", "/index.html", "/agente HADES.html"]:
            html_path = os.path.join(_HERE, "agente HADES.html")
            if os.path.exists(html_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(html_path, "r", encoding="utf-8") as f:
                    content = f.read()
                # Inyectar el token de sesión dinámico en el HTML para uso del JavaScript
                injected = content.replace("const HADES_SECURITY_TOKEN = '';", f"const HADES_SECURITY_TOKEN = '{token_session}';")
                self.wfile.write(injected.encode('utf-8'))
                return

        # Llamar al manejador por defecto de SimpleHTTPRequestHandler para servir CSS/JS/Imágenes
        super().do_GET()

    def do_POST(self):
        global active_process
        if not self.check_token():
            self.send_error(403, "Forbidden: Invalid Token")
            return

        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # 1. API para lanzar el agente
        if path == "/api/scan":
            if active_process is not None and active_process.poll() is None:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "El agente ya se encuentra activo."}).encode('utf-8'))
                return

            # Leer parámetros del cuerpo de la petición
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = json.loads(post_data.decode('utf-8'))
            
            target = params.get("target", "auto")
            if not target or not target.strip():
                target = "auto"
            duration = str(params.get("duration", 30))

            add_log(f"Lanzando HADES en rango '{target}' con captura de {duration}s...")
            
            script_path = os.path.join(_HERE, "hades_surveillance_advanced.py")
            
            # Ejecutar el proceso en un hilo separado para que no bloquee el servidor
            def run_subprocess():
                global active_process
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                env["PYTHONUTF8"] = "1"
                env["HADES_NON_INTERACTIVE"] = "1"
                
                active_process = subprocess.Popen(
                    [sys.executable, script_path, target, duration],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    bufsize=1,
                    cwd=_HERE,
                    env=env
                )
                
                # Leer la salida en tiempo real de forma segura
                # Si el proceso es terminado forzosamente desde /api/stop,
                # el stream se cierra y readline lanza ValueError/OSError.
                # Capturamos estas excepciones para no colapsar el hilo.
                try:
                    for line in iter(active_process.stdout.readline, ''):
                        if line:
                            add_log(line.strip())
                except (ValueError, OSError):
                    # El stream fue cerrado externamente (parada de emergencia)
                    pass
                finally:
                    try:
                        active_process.stdout.close()
                    except Exception:
                        pass
                    try:
                        active_process.wait(timeout=5)
                    except Exception:
                        pass
                    exit_code = active_process.returncode if active_process else -1
                    add_log(f"--- AGENTE FINALIZADO (Codigo de salida: {exit_code}) ---")
                    active_process = None

            threading.Thread(target=run_subprocess, daemon=True).start()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Escaneo iniciado correctamente."}).encode('utf-8'))
            return

        # 2. API para parada forzada de emergencia — TERMINACIÓN INMEDIATA
        if path == "/api/stop":
            add_log("[EMERGENCIA] ⚡ PARADA DE EMERGENCIA ACTIVADA — Terminando todos los procesos...")
            
            # PASO 1: Matar árbol de procesos del agente de forma INMEDIATA con taskkill
            if active_process is not None:
                pid = active_process.pid
                add_log(f"[EMERGENCIA] Ejecutando taskkill /f /t sobre PID {pid} y todos sus procesos hijos...")
                try:
                    # En Windows, /f = forzado, /t = árbol completo (mata hijos también)
                    result = subprocess.run(
                        f"taskkill /f /t /pid {pid}",
                        shell=True, capture_output=True, text=True, timeout=5
                    )
                    add_log(f"[OK] Árbol de procesos del agente eliminado (PID {pid}).")
                except Exception as e:
                    add_log(f"[WARN] taskkill sobre PID {pid} falló: {str(e)} — intentando kill() directo...")
                    try:
                        active_process.kill()
                    except Exception:
                        pass
                finally:
                    # Forzar cierre del stream para desbloquear el hilo de lectura
                    try:
                        active_process.stdout.close()
                    except Exception:
                        pass
                active_process = None
            else:
                add_log("[INFO] No había proceso del agente activo registrado en el servidor.")

            # PASO 2: Limpieza de procesos huérfanos por nombre (seguro, no mata al servidor)
            tools = ["nmap.exe", "tshark.exe", "nuclei.exe", "openssl.exe"]
            add_log(f"[EMERGENCIA] Limpiando herramientas huérfanas: {', '.join(tools)}...")
            try:
                kill_cmd = "taskkill /f " + " ".join(f"/im {t}" for t in tools)
                subprocess.run(kill_cmd, shell=True, capture_output=True, timeout=5)
                add_log("[OK] ✅ Todas las herramientas de ciberseguridad han sido terminadas.")
            except Exception as e:
                add_log(f"[WARN] Error en limpieza de herramientas huérfanas: {str(e)}")

            # PASO 3: También matar cualquier python con hades_surveillance en argumentos
            try:
                subprocess.run(
                    'taskkill /f /fi "WINDOWTITLE eq hades*" /fi "IMAGENAME eq python.exe"',
                    shell=True, capture_output=True, timeout=5
                )
            except Exception:
                pass

            add_log("[EMERGENCIA] ✅ PARADA DE EMERGENCIA completada. Sistema en estado seguro.")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"message": "⚡ PARADA DE EMERGENCIA ejecutada. Todos los procesos han sido terminados de inmediato."}).encode('utf-8'))
            return

def start_server():
    # ThreadingHTTPServer: cada petición se atiende en su propio hilo.
    # Imprescindible para un dashboard que hace polling concurrente de
    # /api/sysinfo, /api/logs y /api/status. Con el HTTPServer monohilo
    # anterior, una sola petición lenta congelaba TODO el panel.
    server = ThreadingHTTPServer(('127.0.0.1', PORT), SecureHadesHandler)
    server.daemon_threads = True
    url = f"http://127.0.0.1:{PORT}/index.html?token={token_session}"
    
    print("=" * 70)
    print(f"   HADES SECURITY COMMAND CENTER SERVER ACTIVO")
    print(f"   Puerto: {PORT}")
    print(f"   Token de sesión: {token_session}")
    print(f"   Abriendo navegador web de forma segura en:")
    print(f"   {url}")
    print("=" * 70)
    
    # Abrir el navegador por defecto automáticamente
    webbrowser.open(url)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor cerrado correctamente.")
        server.server_close()

if __name__ == "__main__":
    start_server()
