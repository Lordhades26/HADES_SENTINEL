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


def validate_target_or_url(value, cidr_ok=True):
    """Acepta una URL HTTP(S) o un objetivo de red validado."""
    return validate_url(value) or validate_target(value, cidr_ok=cidr_ok)
