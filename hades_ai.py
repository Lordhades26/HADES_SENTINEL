"""Configuración compartida para la capa consultiva de IA de HADES.

Este módulo no decide riesgo ni ejecuta acciones. Centraliza únicamente el
cliente local de Ollama y el entorno mínimo permitido a procesos secundarios.
"""

import json
import os
import time
import urllib.request
from urllib.parse import urlparse


DEFAULT_MODEL = "HADES-SENTINEL-ANALYST:1.0.0"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
CONSULTATIVE_LABEL = (
    "COMENTARIO CONSULTIVO DE IA — NO VERIFICADO\n"
    "No altera hallazgos, severidad ni puntuación determinista; requiere "
    "validación humana."
)


def _integer_setting(name, default, minimum=0):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def normalize_ollama_generate_url(value):
    """Valida un endpoint HTTP(S) exacto de ``/api/generate``.

    No se aceptan credenciales embebidas, query strings ni fragmentos, para
    evitar que configuración externa convierta la llamada local en una fuga de
    evidencia o en una URL ambigua.
    """
    candidate = str(value or "").strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("HADES_OLLAMA_URL debe usar http o https.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("HADES_OLLAMA_URL no admite credenciales embebidas.")
    if parsed.path.rstrip("/") != "/api/generate":
        raise ValueError("HADES_OLLAMA_URL debe apuntar exactamente a /api/generate.")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("HADES_OLLAMA_URL no admite parámetros, query ni fragmento.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("HADES_OLLAMA_URL contiene un puerto inválido.") from exc
    return candidate.rstrip("/")


try:
    OLLAMA_URL = normalize_ollama_generate_url(
        os.environ.get("HADES_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    )
except ValueError:
    OLLAMA_URL = DEFAULT_OLLAMA_URL

HADES_MODEL = os.environ.get("HADES_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
AI_TIMEOUT_SECONDS = _integer_setting("HADES_AI_TIMEOUT", 300, minimum=1)
AI_RETRIES = _integer_setting("HADES_AI_RETRIES", 0, minimum=0)
AI_BUDGET_SECONDS = _integer_setting("HADES_AI_BUDGET", 1200, minimum=1)
AI_BACKOFF_SECONDS = _integer_setting("HADES_AI_BACKOFF", 3, minimum=0)


def build_generate_payload(
    prompt,
    model=None,
    *,
    num_predict=640,
    temperature=0,
    keep_alive="5m",
):
    """Construye una solicitud acotada y no-streaming para Ollama."""
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("El prompt de IA no puede estar vacío.")
    return {
        "model": model or HADES_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": keep_alive,
        "options": {
            "num_predict": int(num_predict),
            "temperature": temperature,
        },
    }


class OllamaResponseError(RuntimeError):
    """Ollama informó un error dentro de una respuesta HTTP 200."""


def stream_generate(url, payload, timeout, *, opener=None, monotonic=time.monotonic):
    """Genera en streaming y devuelve ``(datos, parcial)``.

    Sin streaming, una CPU lenta agotaba el límite y se perdía todo lo generado.
    Al vencer ``timeout`` se corta la conexión (Ollama cancela la generación) y
    se conserva el texto recibido; si aún no hay texto se propaga TimeoutError.
    """
    body = json.dumps({**payload, "stream": True}).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    opener = urllib.request.urlopen if opener is None else opener
    deadline = monotonic() + timeout
    partes, final, completa = [], {}, False
    try:
        with opener(request, timeout=timeout) as response:
            for line in response:
                if not line.strip():
                    continue
                item = json.loads(line)
                if item.get("error"):
                    raise OllamaResponseError(str(item["error"])[:300])
                partes.append(item.get("response") or "")
                # Una respuesta única sin campo ``done`` también es completa.
                if item.get("done", True):
                    final, completa = item, True
                    break
                if monotonic() >= deadline:
                    break
    except OSError:
        if not "".join(partes).strip():
            raise
    texto = "".join(partes)
    if not completa and not texto.strip():
        raise TimeoutError("timed out")
    return {**final, "response": texto}, not completa


def format_consultative_output(text):
    """Etiqueta inequívocamente cualquier texto generado por el modelo."""
    body = str(text or "").strip() or "[IA] Sin respuesta del modelo."
    return f"{CONSULTATIVE_LABEL}\n\n{body}"


_BASE_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
)
_HADES_ENV_KEYS = (
    "HADES_MODEL",
    "HADES_OLLAMA_URL",
    "HADES_AI_TIMEOUT",
    "HADES_AI_RETRIES",
    "HADES_AI_BUDGET",
    "HADES_AI_BACKOFF",
    "HADES_SKIP_AI",
    "HADES_NMAP_HOST_TIMEOUT",
    # Sin estas, el dashboard aceptaba un alcance/config que el motor hijo no veía.
    "HADES_ALCANCE",
    "HADES_ASSET_PROFILE_TIMEOUT",
    "HADES_SNMP_COMMUNITIES",
    "HADES_DISCOVERY_ONLINK_FLAGS",
    "HADES_DISCOVERY_ROUTED_FLAGS",
    "HADES_DISCOVERY_TIMEOUT",
)


def safe_subprocess_env(source=None):
    """Devuelve un entorno mínimo sin credenciales para procesos del agente."""
    source = os.environ if source is None else source
    env = {}
    for key in _BASE_ENV_KEYS + _HADES_ENV_KEYS:
        value = source.get(key)
        if value is not None:
            env[key] = str(value)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["HADES_NON_INTERACTIVE"] = "1"
    return env
