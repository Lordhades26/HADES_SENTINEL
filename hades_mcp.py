import json
import subprocess
import sys
import shutil
import os
from typing import Dict, Optional

# Common Windows paths for security tools
WIN_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Wireshark",
    r"C:\Strawberry\perl\bin",
    r"C:\Program Files\OpenSSL-Win64\bin",
    r"C:\Program Files\OpenSSL\bin"
]

def resolve_tool(tool: str) -> Optional[str]:
    # 1. Check system PATH
    exe = shutil.which(tool)
    if exe: return exe
    
    # 2. Check common Windows paths
    if os.name == 'nt':
        exts = ['.exe', '.bat', '.pl']
        for p in WIN_PATHS:
            for ext in exts:
                full = os.path.join(p, tool + ext)
                if os.path.exists(full):
                    return full
    return None

def run_tool(tool: str, args: str):
    try:
        tool_exe = resolve_tool(tool)
        
        # Special case for Nikto on Windows (cloned repo)
        if tool == "nikto" and os.name == 'nt' and not tool_exe:
            nikto_pl = os.path.join(os.path.expanduser("~"), "Desktop", "HADES ECOSYSTEM", "tools", "nikto", "program", "nikto.pl")
            perl_exe = resolve_tool("perl")
            if os.path.exists(nikto_pl) and perl_exe:
                tool_exe = perl_exe
                args = f'"{nikto_pl}" {args}'
            else:
                return f"Error: Nikto or Perl not found. (Expected Nikto at: {nikto_pl})"

        if not tool_exe:
            return f"Error: Tool {tool} not found in system PATH or common locations."
        
        if os.name == 'nt':
            # Handle .pl files via perl
            if tool_exe.endswith(".pl"):
                perl = resolve_tool("perl") or "perl"
                cmd = f'"{perl}" "{tool_exe}" {args}'
            else:
                cmd = f'"{tool_exe}" {args}'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
        else:
            import shlex
            cmd = [tool_exe] + shlex.split(args)
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
        return res.stdout if res.returncode == 0 else (res.stdout + res.stderr)
    except Exception as e:
        return str(e)

def get_tools_status():
    tools = ['nmap', 'nikto', 'openssl', 'tshark', 'curl', 'python3', 'ollama', 'perl']
    status = {}
    for t in tools:
        found = resolve_tool(t) is not None
        if t == 'nikto' and not found:
             found = os.path.exists(os.path.join(os.path.expanduser("~"), "Desktop", "HADES ECOSYSTEM", "tools", "nikto", "program", "nikto.pl"))
        status[t] = "INSTALLED" if found else "MISSING"
    return status

def handle_request(request: Dict):
    method = request.get("method")
    params = request.get("params", {})

    if method == "list_tools":
        return get_tools_status()
    elif method == "nmap_scan":
        target = params.get("target", "127.0.0.1")
        return run_tool("nmap", f"-sV -T4 {target}")
    elif method == "nikto_audit":
        url = params.get("url")
        if not url: return "Error: URL parameter required."
        return run_tool("nikto", f"-h {url} -maxtime 60")
    elif method == "ollama_query":
        prompt = params.get("prompt")
        model = params.get("model", "HADES-AUTO:latest")
        return run_tool("ollama", f"run {model} \"{prompt}\"")
    else:
        return {"error": f"Method '{method}' not found"}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            raw_input = " ".join(sys.argv[1:])
            req = json.loads(raw_input)
            print(json.dumps({"result": handle_request(req)}))
        except Exception as e:
            print(json.dumps({"error": str(e), "raw_input": raw_input}))
    else:
        for line in sys.stdin:
            if not line.strip(): continue
            try:
                req = json.loads(line)
                res = handle_request(req)
                print(json.dumps({"result": res}))
                sys.stdout.flush()
            except Exception as e:
                print(json.dumps({"error": str(e)}))
                sys.stdout.flush()
