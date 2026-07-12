"""WebAuthn (Windows Hello) auth para HADES SENTINEL.

Diseño:
- Single-user, primer registro = dueño del agente. Re-registro requiere borrar
  manualmente `.hades_credentials.json` (fail-safe ante robo de equipo).
- User verification REQUIRED: exige biometría O PIN del dispositivo (no solo
  presencia). Sin user verification el flow se rechaza.
- RP ID = "localhost" porque los navegadores aceptan WebAuthn sin TLS solo
  para localhost/127.0.0.1.
- Storage `.hades_credentials.json` protegido con HMAC-SHA256 contra tampering
  (clave publica no es secreta pero un cambio de clave permitiria login de
  atacante con su propio dispositivo).
- Sesiones in-memory: mueren con el server. Cierre = logout total.
- Challenges con TTL 60s, consumo unico (anti-replay).
"""
import os
import json
import hmac
import time
import base64
import hashlib
import secrets
import threading

import webauthn
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------
RP_ID = "localhost"
RP_NAME = "HADES SENTINEL"
# Aceptamos ambos origenes porque el navegador puede llegar por 127.0.0.1
# o por localhost segun como se abra la URL.
EXPECTED_ORIGINS = ["http://localhost:8080", "http://127.0.0.1:8080"]
USER_NAME = "hades_owner"
USER_DISPLAY_NAME = "HADES Owner"
SESSION_TTL_SECONDS = 8 * 3600
CHALLENGE_TTL_SECONDS = 60

_HERE = os.path.dirname(os.path.abspath(__file__))
CRED_FILE = os.path.join(_HERE, ".hades_credentials.json")
SALT_FILE = os.path.join(_HERE, ".hades_machine_salt")

# ---------------------------------------------------------------------------
# Estado en memoria
# ---------------------------------------------------------------------------
_pending = {}     # challenge_id -> {type, challenge, user_id?, expires_at}
_sessions = {}    # sid -> {created_at, expires_at}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# HMAC del storage. La sal se genera al primer arranque y se persiste; protege
# .hades_credentials.json contra modificaciones manuales (un atacante con
# acceso al disco podria inyectar su credencial, pero no firmar el archivo
# sin la sal).
# ---------------------------------------------------------------------------
def _load_machine_salt():
    if os.path.exists(SALT_FILE):
        try:
            data = open(SALT_FILE, "rb").read()
            if len(data) >= 32:
                return data
        except Exception:
            pass
    salt = secrets.token_bytes(32)
    try:
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    except Exception:
        pass
    return salt

_MACHINE_SALT = _load_machine_salt()

def _hmac_of(data: bytes) -> str:
    return hmac.new(_MACHINE_SALT, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Storage de credentials (JSON + HMAC)
# ---------------------------------------------------------------------------
def _credentials_load() -> list:
    if not os.path.exists(CRED_FILE):
        return []
    try:
        with open(CRED_FILE, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
        payload = json.dumps(wrapper["data"], sort_keys=True).encode("utf-8")
        if not hmac.compare_digest(_hmac_of(payload), wrapper.get("hmac", "")):
            # Tampering: tratar como sin credentials.
            return []
        return wrapper["data"]
    except Exception:
        return []

def _credentials_save(creds: list):
    payload = json.dumps(creds, sort_keys=True).encode("utf-8")
    wrapper = {"data": creds, "hmac": _hmac_of(payload)}
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2)

def has_credentials() -> bool:
    return len(_credentials_load()) > 0


# ---------------------------------------------------------------------------
# Sesiones
# ---------------------------------------------------------------------------
def session_create() -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _sessions[sid] = {"created_at": now, "expires_at": now + SESSION_TTL_SECONDS}
    return sid

def session_valid(sid: str) -> bool:
    if not sid:
        return False
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return False
        if time.time() > s["expires_at"]:
            del _sessions[sid]
            return False
    return True

def session_revoke(sid: str):
    with _lock:
        _sessions.pop(sid, None)


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------
def _gc_pending_locked():
    now = time.time()
    expired = [k for k, v in _pending.items() if v["expires_at"] < now]
    for k in expired:
        del _pending[k]

def _b64url_decode(s: str) -> bytes:
    # base64url decode tolerante a padding faltante
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# WebAuthn — REGISTRO
# ---------------------------------------------------------------------------
def begin_registration(authenticated_sid: str = None) -> dict:
    """Genera options para navigator.credentials.create.
    Solo permitido si NO hay credentials previas (single-user inicial) o si
    el caller ya esta autenticado (re-registro consciente)."""
    if has_credentials() and not session_valid(authenticated_sid):
        raise PermissionError("Ya hay un dispositivo registrado. Inicia sesion para re-registrar.")
    challenge = secrets.token_bytes(32)
    chal_id = secrets.token_urlsafe(16)
    user_id = secrets.token_bytes(32)
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=USER_NAME,
        user_id=user_id,
        user_display_name=USER_DISPLAY_NAME,
        challenge=challenge,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    with _lock:
        _pending[chal_id] = {
            "type": "register",
            "challenge": challenge,
            "user_id": user_id,
            "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
        }
        _gc_pending_locked()
    return {
        "challenge_id": chal_id,
        "options": json.loads(webauthn.options_to_json(options)),
    }

def complete_registration(chal_id: str, credential: dict) -> str:
    """Verifica respuesta del navegador y persiste credential. Devuelve sid."""
    with _lock:
        entry = _pending.pop(chal_id, None)
    if not entry or entry["type"] != "register" or time.time() > entry["expires_at"]:
        raise ValueError("Challenge invalido o expirado")
    verified = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=entry["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=EXPECTED_ORIGINS,
        require_user_verification=True,
    )
    creds = _credentials_load()
    creds.append({
        "credential_id": _b64url_encode(verified.credential_id),
        "public_key": _b64url_encode(verified.credential_public_key),
        "sign_count": verified.sign_count,
        "user_id": _b64url_encode(entry["user_id"]),
        "registered_at": int(time.time()),
    })
    _credentials_save(creds)
    return session_create()


# ---------------------------------------------------------------------------
# WebAuthn — AUTENTICACION
# ---------------------------------------------------------------------------
def begin_authentication() -> dict:
    creds = _credentials_load()
    if not creds:
        raise ValueError("No hay dispositivos registrados")
    challenge = secrets.token_bytes(32)
    chal_id = secrets.token_urlsafe(16)
    allow = [
        PublicKeyCredentialDescriptor(id=_b64url_decode(c["credential_id"]))
        for c in creds
    ]
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    with _lock:
        _pending[chal_id] = {
            "type": "login",
            "challenge": challenge,
            "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
        }
        _gc_pending_locked()
    return {
        "challenge_id": chal_id,
        "options": json.loads(webauthn.options_to_json(options)),
    }

def complete_authentication(chal_id: str, credential: dict) -> str:
    with _lock:
        entry = _pending.pop(chal_id, None)
    if not entry or entry["type"] != "login" or time.time() > entry["expires_at"]:
        raise ValueError("Challenge invalido o expirado")
    cred_id = credential.get("id") or credential.get("rawId")
    if not cred_id:
        raise ValueError("Credential id ausente en respuesta")
    creds = _credentials_load()
    matched = next((c for c in creds if c["credential_id"] == cred_id), None)
    if not matched:
        raise ValueError("Credential no reconocida")
    verified = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=entry["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=EXPECTED_ORIGINS,
        credential_public_key=_b64url_decode(matched["public_key"]),
        credential_current_sign_count=matched["sign_count"],
        require_user_verification=True,
    )
    matched["sign_count"] = verified.new_sign_count
    matched["last_login_at"] = int(time.time())
    _credentials_save(creds)
    return session_create()
