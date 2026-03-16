# app/security.py
import collections
import logging
import os
import re
import time
import base64
import hashlib
import binascii
import secrets
from typing import Any, Dict

import jwt
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)


# -----------------------
# Password hashing (PBKDF2)
# -----------------------

def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) < 8:
        raise HTTPException(status_code=400, detail="password too short (min 8 characters)")

    # Politique de complexité minimale pour un service médical
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=400, detail="password must contain at least one uppercase letter")
    if not re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="password must contain at least one digit")

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, 100_000)
    return binascii.hexlify(salt + dk).decode("ascii")


def verify_password(password: str, stored: str) -> bool:
    try:
        raw = binascii.unhexlify(stored.encode("ascii"))
        salt = raw[:16]
        dk_stored = raw[16:]
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return secrets.compare_digest(dk, dk_stored)
    except Exception:
        return False


# -----------------------
# JWT access token
# -----------------------

def _jwt_secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError("JWT_SECRET is missing")
    return s


def access_ttl_seconds() -> int:
    return int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900"))  # 15 min


def create_access_token(*, user_id: str, is_admin: bool) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "adm": bool(is_admin),
        "iat": now,
        "exp": now + access_ttl_seconds(),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid access token")


bearer_scheme = HTTPBearer(auto_error=True)


# -----------------------
# Refresh token + hashing (DB)
# -----------------------

def _refresh_pepper() -> bytes:
    p = os.environ.get("REFRESH_TOKEN_PEPPER")
    if not p:
        raise RuntimeError("REFRESH_TOKEN_PEPPER is missing")
    return p.encode("utf-8")


def refresh_ttl_seconds() -> int:
    return int(os.environ.get("REFRESH_TOKEN_TTL_SECONDS", str(30 * 24 * 3600)))  # 30 days


def new_refresh_token() -> str:
    # 32 bytes random -> base64url
    raw = os.urandom(32)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def hash_refresh_token(token: str) -> str:
    # SHA256(pepper || token) -> hex
    h = hashlib.sha256(_refresh_pepper() + token.encode("utf-8")).hexdigest()
    return h


# -----------------------
# CSRF double-submit token (cookie + header)
# -----------------------

def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def require_csrf(header_value: str | None, cookie_value: str | None):
    if not header_value or not cookie_value:
        raise HTTPException(status_code=403, detail="missing csrf token")
    if not secrets.compare_digest(header_value, cookie_value):
        raise HTTPException(status_code=403, detail="bad csrf token")


# -----------------------
# Admin auth helper (shared by all admin routers)
# Accepts x-admin-secret header OR JWT Bearer with adm=true
# -----------------------

def require_admin(request: Any) -> None:
    """Vérifie que la requête vient d'un admin.

    Accepte :
      - En-tête  x-admin-secret: <ADMIN_SECRET>
      - Bearer JWT avec claim adm=true
    """
    expected = os.environ.get("ADMIN_SECRET")
    got = request.headers.get("x-admin-secret")
    if expected and got == expected:
        return

    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        try:
            payload = decode_access_token(token)
            if payload.get("adm"):
                return
        except Exception:
            pass

    raise HTTPException(status_code=401, detail="unauthorized")


# -----------------------
# Login rate limiting (in-memory, single-process)
# Max _RATE_LIMIT_MAX attempts per IP within _RATE_LIMIT_WINDOW seconds
# -----------------------

_RATE_LIMIT_WINDOW = 900   # 15 min
_RATE_LIMIT_MAX    = 10    # tentatives max par fenêtre

_login_attempts: dict[str, collections.deque] = collections.defaultdict(collections.deque)


def check_login_rate_limit(ip: str) -> None:
    """Lève HTTP 429 si l'IP a dépassé la limite de tentatives de login."""
    now = time.time()
    dq = _login_attempts[ip]
    # Purge les tentatives hors fenêtre
    while dq and now - dq[0] > _RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail="too many login attempts — retry in 15 minutes",
            headers={"Retry-After": str(_RATE_LIMIT_WINDOW)},
        )
    dq.append(now)


# -----------------------
# Email encryption (Fernet / AES-128-CBC)
# Set EMAIL_ENCRYPTION_KEY to a valid Fernet key (generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
# If unset, emails are stored as plaintext with a startup warning.
# -----------------------

_fernet = None
_EMAIL_KEY_RAW = os.environ.get("EMAIL_ENCRYPTION_KEY", "")

if not _EMAIL_KEY_RAW:
    logger.warning(
        "EMAIL_ENCRYPTION_KEY not set — email addresses will be stored as plaintext. "
        "Set this variable in production."
    )


def _get_fernet():
    global _fernet, _EMAIL_KEY_RAW
    if _EMAIL_KEY_RAW and _fernet is None:
        from cryptography.fernet import Fernet
        _fernet = Fernet(_EMAIL_KEY_RAW.encode())
    return _fernet


def encrypt_email(email_norm: str) -> bytes:
    """Encrypt email for storage. Falls back to UTF-8 if no key is configured."""
    f = _get_fernet()
    if f is None:
        return email_norm.encode("utf-8")
    return f.encrypt(email_norm.encode("utf-8"))


def decrypt_email(data: bytes | memoryview) -> str:
    """Decrypt email from storage. Handles both encrypted and legacy plaintext."""
    if isinstance(data, memoryview):
        data = bytes(data)
    f = _get_fernet()
    if f is not None:
        try:
            from cryptography.fernet import InvalidToken
            return f.decrypt(data).decode("utf-8")
        except (InvalidToken, Exception):
            # Legacy plaintext row — decode directly
            pass
    return data.decode("utf-8")
