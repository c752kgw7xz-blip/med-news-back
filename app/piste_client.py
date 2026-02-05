import os
import time
import base64
import httpx
from typing import Any

# cache token en mémoire (process)
_TOKEN = {"value": None, "exp": 0}


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _get_piste_endpoints() -> tuple[str, str]:
    """
    Détermine les endpoints OAuth + API selon l'env.
    """
    env = os.environ.get("PISTE_ENV", "sandbox").lower()

    if env == "prod":
        return (
            "https://oauth.piste.gouv.fr/api/oauth/token",
            "https://api.piste.gouv.fr/dila/legifrance/lf-engine-app",
        )
    else:
        return (
            "https://sandbox-oauth.piste.gouv.fr/api/oauth/token",
            "https://sandbox-api.piste.gouv.fr/dila/legifrance/lf-engine-app",
        )


def get_piste_token() -> str:
    client_id = os.environ.get("PISTE_CLIENT_ID")
    client_secret = os.environ.get("PISTE_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise RuntimeError("Missing PISTE_CLIENT_ID / PISTE_CLIENT_SECRET")

    token_url, _ = _get_piste_endpoints()

    now = int(time.time())
    if _TOKEN["value"] and now < _TOKEN["exp"] - 30:
        return _TOKEN["value"]

    headers = {
        "Authorization": _basic_auth_header(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        # "scope": "openid",  # à activer si requis
    }

    r = httpx.post(token_url, headers=headers, data=data, timeout=20)
    r.raise_for_status()
    payload = r.json()

    access_token = payload["access_token"]
    expires_in = int(payload.get("expires_in", 300))

    _TOKEN["value"] = access_token
    _TOKEN["exp"] = now + expires_in

    return access_token


def piste_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """
    Appel POST vers l'API Légifrance (PISTE) avec OAuth2.
    """
    _, api_base = _get_piste_endpoints()
    token = get_piste_token()

    url = api_base.rstrip("/") + path

    r = httpx.post(
        url,
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()
