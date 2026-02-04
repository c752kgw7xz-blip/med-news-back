# app/auth_routes.py
import time
import psycopg
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from app.db import get_conn
from app.security import (
    verify_password,
    create_access_token,
    new_refresh_token,
    hash_refresh_token,
    refresh_ttl_seconds,
    new_csrf_token,
    require_csrf,
)

router = APIRouter()


# -----------------------
# Models
# -----------------------

class LoginPayload(BaseModel):
    email: EmailStr
    password: str


# -----------------------
# Cookie settings
# -----------------------

REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"

def set_auth_cookies(resp: Response, refresh_token: str, csrf_token: str):
    # Refresh token: HttpOnly, Secure
    resp.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/auth",
        max_age=refresh_ttl_seconds(),
    )
    # CSRF token: readable by JS (double-submit)
    resp.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        httponly=False,
        secure=True,
        samesite="lax",
        path="/auth",
        max_age=refresh_ttl_seconds(),
    )

def clear_auth_cookies(resp: Response):
    resp.delete_cookie(REFRESH_COOKIE, path="/auth")
    resp.delete_cookie(CSRF_COOKIE, path="/auth")


# -----------------------
# Routes
# -----------------------

@router.post("/auth/login")
def login(payload: LoginPayload, response: Response):
    email_norm = payload.email.strip().lower()

    # lookup deterministic = SHA256(email_norm)
    import hashlib
    email_lookup = hashlib.sha256(email_norm.encode("utf-8")).digest()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password_hash, is_admin FROM users WHERE email_lookup = %s;",
                (email_lookup,),
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=401, detail="invalid credentials")

            user_id, password_hash, is_admin = row

            if not verify_password(payload.password, password_hash):
                raise HTTPException(status_code=401, detail="invalid credentials")

            # create refresh token row (hashed)
            refresh = new_refresh_token()
            refresh_hash = hash_refresh_token(refresh)
            expires_at = int(time.time()) + refresh_ttl_seconds()

            cur.execute(
                """
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, to_timestamp(%s))
                """,
                (user_id, refresh_hash, expires_at),
            )

    access = create_access_token(user_id=str(user_id), is_admin=bool(is_admin))
    csrf = new_csrf_token()
    set_auth_cookies(response, refresh, csrf)

    return {"access_token": access, "token_type": "bearer"}


@router.post("/auth/refresh")
def refresh(request: Request, response: Response):
    refresh_cookie = request.cookies.get(REFRESH_COOKIE)
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    csrf_header = request.headers.get("x-csrf-token")
    require_csrf(csrf_header, csrf_cookie)

    if not refresh_cookie:
        raise HTTPException(status_code=401, detail="missing refresh token")

    old_hash = hash_refresh_token(refresh_cookie)
    now = int(time.time())
    new_refresh = new_refresh_token()
    new_hash = hash_refresh_token(new_refresh)
    new_expires = now + refresh_ttl_seconds()

    with get_conn() as conn:
        with conn.cursor() as cur:
            # find valid token
            cur.execute(
                """
                SELECT id, user_id
                FROM refresh_tokens
                WHERE token_hash = %s
                  AND revoked_at IS NULL
                  AND expires_at > now()
                """,
                (old_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="invalid refresh token")

            old_id, user_id = row

            # rotate: create new row
            cur.execute(
                """
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, to_timestamp(%s))
                RETURNING id
                """,
                (user_id, new_hash, new_expires),
            )
            new_id = cur.fetchone()[0]

            # revoke old + link
            cur.execute(
                """
                UPDATE refresh_tokens
                SET revoked_at = now(), replaced_by = %s
                WHERE id = %s
                """,
                (new_id, old_id),
            )

            # fetch is_admin for access token
            cur.execute("SELECT is_admin FROM users WHERE id = %s;", (user_id,))
            is_admin = bool(cur.fetchone()[0])

    access = create_access_token(user_id=str(user_id), is_admin=is_admin)
    csrf = new_csrf_token()
    set_auth_cookies(response, new_refresh, csrf)

    return {"access_token": access, "token_type": "bearer"}


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    refresh_cookie = request.cookies.get(REFRESH_COOKIE)
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    csrf_header = request.headers.get("x-csrf-token")
    require_csrf(csrf_header, csrf_cookie)

    if refresh_cookie:
        token_hash = hash_refresh_token(refresh_cookie)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE refresh_tokens
                    SET revoked_at = now()
                    WHERE token_hash = %s AND revoked_at IS NULL
                    """,
                    (token_hash,),
                )

    clear_auth_cookies(response)
    return {"ok": True}
