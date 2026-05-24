#!/usr/bin/env python3
import os, sys, json, time, signal, shutil, subprocess, argparse, re
from datetime import datetime
from pathlib import Path

HADES_VERSION = "1.3.0"

# --- WINDOWS ROBUST RESOLVER ---
WIN_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Wireshark",
    r"C:\Strawberry\perl\bin",
    r"C:\Program Files\OpenSSL-Win64\bin",
    r"C:\Program Files\OpenSSL\bin"
]

def resolve_tool_path(tool):
    exe = shutil.which(tool)
    if exe: return exe
    if os.name == 'nt':
        for p in WIN_PATHS:
            for ext in ['.exe', '.bat', '.pl']:
                full = os.path.join(p, tool + ext)
                if os.path.exists(full): return full
    return tool

def update_env_path():
    if os.name == 'nt':
        current_path = os.environ.get("PATH", "")
        for p in WIN_PATHS:
            if os.path.exists(p) and p not in current_path:
                current_path = p + os.pathsep + current_path
        os.environ["PATH"] = current_path

update_env_path()
# ------------------------------

TOOL_CATALOG = {
    "nmap":         {"category":"recon",   "desc":"Escáner de red y puertos"},
    "nikto":        {"category":"web",     "desc":"Escáner vulnerabilidades web"},
    "openssl":      {"category":"misc",    "desc":"Herramientas SSL/TLS"},
    "tshark":       {"category":"traffic", "desc":"Análisis de tráfico"},
    "curl":         {"category":"misc",    "desc":"Cliente HTTP"},
    "ollama":       {"category":"ai",      "desc":"Motor de IA local"},
}

def detect_tools():
    installed = {}
    for t, m in TOOL_CATALOG.items():
        # Special case for Nikto on Windows
        path = resolve_tool_path(t)
        if t == "nikto" and os.name == "nt" and not shutil.which(t):
            nikto_pl = os.path.join(os.path.expanduser("~"), "Desktop", "HADES ECOSYSTEM", "tools", "nikto", "program", "nikto.pl")
            if os.path.exists(nikto_pl):
                path = nikto_pl
        
        if shutil.which(t) or (os.path.exists(path) if path else False):
            installed[t] = m
    return installed

def detect_os():
    return sys.platform

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")

def run_cmd(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1

class HadesEngine:
    def __init__(self):
        self.tools = detect_tools()
        self.ollama_url = "http://127.0.0.1:11434/api/generate"

    def _has(self, t):
        return t in self.tools

    def _ask(self, prompt, model="HADES-AUTO:latest"):
        payload = {"model": model, "prompt": prompt, "stream": False}
        try:
            import urllib.request
            req = urllib.request.Request(self.ollama_url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=30) as res:
                return json.loads(res.read().decode('utf-8')).get("response", "")
        except Exception as e:
            return f"Error IA: {str(e)}"

    def quick_scan(self, target):
        log(f"Iniciando escaneo rápido en {target}...", "HADES")
        nmap_bin = resolve_tool_path("nmap")
        if not os.path.exists(nmap_bin) and not shutil.which("nmap"):
            log("Nmap no detectado. Por favor instala Nmap.", "WARN")
            return
        
        # Use full path with quotes for Windows
        cmd = f'"{nmap_bin}" -F {target}'
        stdout, stderr, code = run_cmd(cmd)
        print(stdout)
        
        analysis = self._ask(f"Analiza estos puertos abiertos en {target} y da un consejo de seguridad corto:\n{stdout}")
        print(f"\n[IA ANALYSIS]\n{analysis}\n")

    def status(self):
        print(f"\n--- HADES SYSTEM STATUS (v{HADES_VERSION}) ---")
        print(f"OS: {detect_os()}")
        print(f"Tools Installed: {', '.join(self.tools.keys())}")
        missing = [t for t in TOOL_CATALOG if t not in self.tools]
        if missing:
            print(f"Tools Missing: {', '.join(missing)}")
        print("------------------------------------------\n")

def main():
    parser = argparse.ArgumentParser(description="HADES Local Agent")
    parser.add_argument("command", choices=["scan", "status", "tools"])
    parser.add_argument("target", nargs="?", default="127.0.0.1")
    args = parser.parse_args()

    engine = HadesEngine()
    if args.command == "status" or args.command == "tools":
        engine.status()
    elif args.command == "scan":
        engine.quick_scan(args.target)

if __name__ == "__main__":
    main()
