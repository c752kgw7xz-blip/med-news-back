import os
import time
import base64
import httpx

_TOKEN = {"value": None, "exp": 0}

def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")

def get_piste_token() -> str:
    client_id = os.environ.get("PISTE_CLIENT_ID")
    client_secret = os.environ.get("PISTE_CLIENT_SECRET")
    token_url = os.environ.get("PISTE_TOKEN_URL", "https://sandbox-oauth.piste.gouv.fr/api/oauth/token")

    if not client_id or not client_secret:
        raise RuntimeError("Missing PISTE_CLIENT_ID / PISTE_CLIENT_SECRET")

    now = int(time.time())
    if _TOKEN["value"] and now < _TOKEN["exp"] - 30:
        return _TOKEN["value"]

    headers = {
        "Authorization": _basic_auth_header(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        # selon certaines intégrations PISTE, un scope est requis. Mets-le si l’API le demande.
        # "scope": "openid",
    }

    r = httpx.post(token_url, headers=headers, data=data, timeout=20)
    r.raise_for_status()
    payload = r.json()

    access_token = payload["access_token"]
    expires_in = int(payload.get("expires_in", 300))
    _TOKEN["value"] = access_token
    _TOKEN["exp"] = now + expires_in
    return access_token
