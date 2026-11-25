"""Recuperación conservadora del servicio local de Ollama.

El módulo nunca termina procesos preexistentes ni eleva privilegios. Si el
puerto local está ocupado por un listener no saludable, informa el bloqueo y
deja que HADES continúe sin la capa consultiva de IA.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from typing import Callable, Optional
from urllib.parse import urlparse
import urllib.request

from hades_ai import safe_subprocess_env
from hades_processes import terminate_process_tree


DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
OLLAMA_ORIGINS = "http://127.0.0.1:8080,http://localhost:8080"


@dataclass(frozen=True)
class OllamaRuntimeStatus:
    state: str
    detail: str
    pid: Optional[int] = None
    version: Optional[str] = None


_owned_process = None


def _endpoint_is_supported(endpoint):
    try:
        parsed = urlparse(str(endpoint or "").strip())
        return (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port == 11434
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


def _probe_version(endpoint):
    request = urllib.request.Request(
        f"{endpoint}/api/version",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=1.5) as response:
        return json.loads(response.read().decode("utf-8"))


def _port_is_busy(host="127.0.0.1", port=11434):
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


def _resolve_ollama_binary(source_env=None):
    source_env = os.environ if source_env is None else source_env
    candidates = []
    local_app_data = source_env.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(
            Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe"
        )
    discovered = shutil.which("ollama", path=source_env.get("PATH"))
    if discovered:
        candidates.append(Path(discovered))

    expected_names = {"ollama.exe"} if os.name == "nt" else {"ollama", "ollama.exe"}
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file() and resolved.name.lower() in expected_names:
            return resolved
    return None


def _creation_flags():
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )


def _spawn_ollama(args, **kwargs):
    return subprocess.Popen(args, **kwargs)


def shutdown_owned_ollama():
    """Cierra únicamente el Ollama que inició HADES; nunca uno ajeno."""
    global _owned_process
    process, _owned_process = _owned_process, None
    if process is None or process.poll() is not None:
        return
    try:
        terminate_process_tree(process, timeout=5)
    except Exception:
        pass


def ensure_ollama_available(
    *,
    endpoint=DEFAULT_OLLAMA_ENDPOINT,
    timeout_seconds=45.0,
    source_env=None,
    probe: Optional[Callable] = None,
    port_busy: Optional[Callable] = None,
    resolve_binary: Optional[Callable] = None,
    spawn: Optional[Callable] = None,
    monotonic: Optional[Callable] = None,
    wait: Optional[Callable] = None,
):
    """Comprueba o inicia Ollama sin administrar procesos ajenos."""
    global _owned_process

    source_env = os.environ if source_env is None else source_env
    if str(source_env.get("HADES_SKIP_AI", "")).strip() == "1":
        return OllamaRuntimeStatus(
            "disabled",
            "La capa consultiva de IA está deshabilitada.",
        )
    if not _endpoint_is_supported(endpoint):
        return OllamaRuntimeStatus(
            "unsupported_endpoint",
            "El runtime sólo admite Ollama en loopback local.",
        )

    probe = _probe_version if probe is None else probe
    port_busy = _port_is_busy if port_busy is None else port_busy
    resolve_binary = (
        (lambda: _resolve_ollama_binary(source_env))
        if resolve_binary is None
        else resolve_binary
    )
    spawn = _spawn_ollama if spawn is None else spawn
    monotonic = time.monotonic if monotonic is None else monotonic
    wait = time.sleep if wait is None else wait

    try:
        version_data = probe(endpoint)
        return OllamaRuntimeStatus(
            "healthy",
            "Ollama local disponible.",
            version=str(version_data.get("version") or "") or None,
        )
    except Exception:
        pass

    if port_busy("127.0.0.1", 11434):
        return OllamaRuntimeStatus(
            "blocked_stale_listener",
            "El puerto local de Ollama está ocupado por un servicio no saludable.",
        )

    binary = resolve_binary()
    if binary is None:
        return OllamaRuntimeStatus(
            "missing_binary",
            "Ollama no está instalado en una ruta local verificable.",
        )

    env = safe_subprocess_env(source_env)
    env["OLLAMA_HOST"] = "127.0.0.1:11434"
    env["OLLAMA_ORIGINS"] = OLLAMA_ORIGINS
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": env,
    }
    flags = _creation_flags()
    if flags:
        kwargs["creationflags"] = flags

    try:
        process = spawn([str(binary), "serve"], **kwargs)
    except Exception:
        return OllamaRuntimeStatus(
            "startup_failed",
            "Ollama no pudo iniciarse con el entorno local seguro.",
        )

    # Un Ollama propio anterior que siga vivo pero mudo no debe quedar huérfano.
    shutdown_owned_ollama()
    _owned_process = process
    deadline = monotonic() + max(0.1, float(timeout_seconds))
    while monotonic() < deadline:
        if process.poll() is not None:
            _owned_process = None
            # Otro proceso pudo ganar el puerto entre la comprobación y el arranque.
            try:
                version_data = probe(endpoint)
                return OllamaRuntimeStatus(
                    "healthy",
                    "Ollama local disponible.",
                    version=str(version_data.get("version") or "") or None,
                )
            except Exception:
                pass
            return OllamaRuntimeStatus(
                "startup_failed",
                "El proceso local de Ollama finalizó durante el arranque.",
            )
        try:
            version_data = probe(endpoint)
            return OllamaRuntimeStatus(
                "started",
                "Ollama local iniciado por HADES.",
                pid=process.pid,
                version=str(version_data.get("version") or "") or None,
            )
        except Exception:
            wait(min(0.25, max(0.0, deadline - monotonic())))

    shutdown_owned_ollama()
    return OllamaRuntimeStatus(
        "startup_failed",
        "Ollama no respondió dentro del tiempo de arranque permitido.",
        pid=getattr(process, "pid", None),
    )
