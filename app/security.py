# app/security.py
import os
import time
import base64
import hashlib
import binascii
import secrets
from typing import Any, Dict

import jwt
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


# -----------------------
# Password hashing (PBKDF2)
# -----------------------

def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) < 8:
        raise HTTPException(status_code=400, detail="password too short")

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
