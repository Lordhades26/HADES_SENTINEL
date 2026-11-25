"""Validación única de objetivos antes de invocar herramientas externas."""
import ipaddress
import re
from urllib.parse import urlsplit


_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_URL_PATH_RE = re.compile(r"^(?:/[A-Za-z0-9._~/-]*)?$")


def _is_valid_hostname(value):
    """Valida un hostname DNS real (RFC 1034/1123, forma ASCII)."""
    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or len(hostname) > 253:
        return False
    # Impide que una IPv4 inválida se disfrace de hostname numérico.
    if all(char.isdigit() or char == "." for char in hostname):
        return False
    labels = hostname.split(".")
    return all(_HOST_LABEL_RE.fullmatch(label) for label in labels)


def validate_target(value, cidr_ok=True):
    """Devuelve IP/CIDR/hostname válido sin normalizar, o ``None``.

    Se rechazan tipos no textuales y cualquier valor que empiece con ``-`` antes
    de aplicar validación semántica, para impedir inyección de argumentos.
    """
    if not isinstance(value, str):
        return None
    target = value.strip()
    if not target or target.startswith("-"):
        return None

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if "/" in target:
        if not cidr_ok:
            return None
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            return None

    return target if _is_valid_hostname(target) else None


def validate_url(value):
    """Devuelve una URL HTTP(S) segura para uso en CLI, o ``None``."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url or url.startswith("-"):
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port  # fuerza validación del puerto
    except (TypeError, ValueError):
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment:
        return None
    if not _URL_PATH_RE.fullmatch(parsed.path):
        return None
    host = parsed.hostname
    if host is None or validate_target(host, cidr_ok=False) is None:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    return url


# ── Alcance autorizado ────────────────────────────────────────────────────────
# Una herramienta de auditoría NO debe poder apuntar a Internet ni a rangos
# gigantes por un error de tipeo. Por defecto sólo redes privadas; el operador
# amplía el alcance acordado con HADES_ALCANCE="198.51.100.0/24,10.0.0.0/8".
ALCANCE_POR_DEFECTO = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                       "127.0.0.0/8", "::1/128",
                       "169.254.0.0/16", "fc00::/7", "fe80::/10")
PREFIJO_MINIMO_IPV4 = 16
PREFIJO_MINIMO_IPV6 = 64


def _redes_autorizadas():
    import os
    valor = os.environ.get("HADES_ALCANCE", "").strip()
    fuentes = [v.strip() for v in valor.split(",") if v.strip()] or list(ALCANCE_POR_DEFECTO)
    redes = []
    for v in fuentes:
        try:
            redes.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            continue
    return redes


def _red_en_alcance(red, redes):
    return any(red.version == r.version and red.subnet_of(r) for r in redes)


def check_scope(target, resolver=None):
    """Devuelve (True, "") si el objetivo cae en el alcance autorizado, o
    (False, motivo). `resolver(host) -> [ip, ...]` permite tests sin DNS."""
    if target == "auto":
        return True, ""
    if validate_target(target) is None:
        return False, "objetivo inválido"
    redes = _redes_autorizadas()
    try:
        red = ipaddress.ip_network(target, strict=False)
    except ValueError:
        red = None
    if red is not None:
        minimo = PREFIJO_MINIMO_IPV4 if red.version == 4 else PREFIJO_MINIMO_IPV6
        if red.prefixlen < minimo:
            return False, f"rango demasiado amplio (/{red.prefixlen}; mínimo /{minimo})"
        if not _red_en_alcance(red, redes):
            return False, f"{target} fuera del alcance autorizado (HADES_ALCANCE)"
        return True, ""
    # Hostname: todas las IPs a las que resuelve deben estar en alcance.
    if resolver is None:
        import socket

        def resolver(host):
            return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    try:
        ips = resolver(target)
    except Exception:
        return False, f"no se pudo resolver {target}"
    if not ips:
        return False, f"no se pudo resolver {target}"
    fuera = [ip for ip in ips if not _red_en_alcance(ipaddress.ip_network(ip), redes)]
    if fuera:
        return False, f"{target} resuelve a {', '.join(fuera)}, fuera del alcance autorizado"
    return True, ""


def validate_target_or_url(value, cidr_ok=True):
    """Acepta una URL HTTP(S) o un objetivo de red validado."""
    return validate_url(value) or validate_target(value, cidr_ok=cidr_ok)


def validate_in_scope(value, cidr_ok=True, allow_url=False):
    """Objetivo (o URL) válido Y dentro del alcance autorizado; si no, ``None``."""
    url = validate_url(value) if allow_url else None
    if url is not None:
        host = urlsplit(url).hostname
        return url if check_scope(host)[0] else None
    target = validate_target(value, cidr_ok=cidr_ok)
    if target is None or target == "auto":
        return None
    return target if check_scope(target)[0] else None
