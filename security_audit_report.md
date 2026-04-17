# Rapport d'audit de sécurité — MedNews Backend
**Date :** 2026-03-25
**Scope :** Backend FastAPI, Frontend HTML/JS, scripts/, requirements.txt
**Méthode :** Lecture ligne par ligne de 30+ fichiers — OWASP Top 10, SANS CWE Top 25
**Auditeur :** Claude Sonnet 4.6

---

## Résultats

---

### 🟠 ÉLEVÉ — Rate limiting contournable derrière reverse proxy — auth_routes.py:73

**Catégorie :** Authentification / Brute-force
**Code vulnérable :**
```python
ip = request.client.host if request.client else "unknown"
check_login_rate_limit(ip)
```
**Risque :** Sur Render, `request.client.host` retourne l'IP du proxy interne de Render (ex. `10.x.x.x`), **pas l'IP réelle du client**. Conséquences :
1. **Contournement total** : un attaquant peut tenter des milliers de logins sans jamais déclencher le rate limit (toutes ses requêtes ont la même « IP » que tout le monde).
2. **DoS possible** : un seul utilisateur légitime échouant 10 fois bloque tous les autres (même bucket IP proxy).

**Correction recommandée :**
```python
# Dans main.py, ajouter le middleware TrustedHostMiddleware avec X-Forwarded-For
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Lire la vraie IP cliente (Render passe X-Forwarded-For)
def _real_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# Dans login() :
ip = _real_ip(request)
check_login_rate_limit(ip)
```

---

### 🟠 ÉLEVÉ — SSRF via /admin/sources/test-feed — sources_routes.py:284-297

**Catégorie :** Server-Side Request Forgery (SSRF)
**Code vulnérable :**
```python
@router.post("/test-feed")
def test_rss_feed(
    request: Request,
    url: str = Query(..., description="URL du flux RSS à tester"),
):
    _require_admin(request)
    # ...
    parsed = fetch_feed(url)   # httpx.get(url) sans restriction
```
**Risque :** Un admin peut déclencher des requêtes HTTP depuis le serveur vers **n'importe quelle URL**, y compris :
- Métadonnées de l'instance cloud (`http://169.254.169.254/latest/meta-data/` sur AWS/GCP/Render)
- Services internes non exposés publiquement
- Exfiltration de tokens de service

Même si la route est admin-only, une compromission de compte admin (credential stuffing, fuite de `ADMIN_SECRET`) ouvre un vecteur SSRF complet.

**Correction recommandée :**
```python
import ipaddress, urllib.parse

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def _validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise HTTPException(400, "Scheme non autorisé")
    import socket
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except Exception:
        raise HTTPException(400, "Hôte invalide")
    for blocked in _BLOCKED_RANGES:
        if ip in blocked:
            raise HTTPException(400, "Adresse IP bloquée (réseau privé)")
```

---

### 🟡 MOYEN — Timing oracle sur énumération d'emails — auth_routes.py:89-95

**Catégorie :** Authentification / Information Disclosure
**Code vulnérable :**
```python
if not row:
    raise HTTPException(status_code=401, detail="invalid credentials")
# ↑ Retour immédiat (~1ms)

if not verify_password(payload.password, password_hash):
    raise HTTPException(status_code=401, detail="invalid credentials")
# ↑ PBKDF2 100 000 itérations (~100ms)
```
**Risque :** La différence de temps de réponse entre un email inexistant (~1ms) et un email valide avec mauvais mot de passe (~100ms) permet à un attaquant d'**énumérer les comptes valides** via timing attack, même avec le rate limiting actif (10 requêtes × 1ms = information extraite avant blocage).

**Correction recommandée :**
```python
# Toujours effectuer la vérification PBKDF2, même si l'utilisateur n'existe pas
DUMMY_HASH = hash_password("Dummy_password_123!")  # constante au démarrage

if not row:
    verify_password(payload.password, DUMMY_HASH)  # même durée
    raise HTTPException(status_code=401, detail="invalid credentials")
```

---

### 🟡 MOYEN — Exposition d'exceptions internes dans les réponses HTTP — sources_routes.py, main.py

**Catégorie :** Information Disclosure
**Code vulnérable :**
```python
# sources_routes.py:171, 181, 191, 201, 211, 235, 252, 276, 325
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))

# main.py:330, 342
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))
```
**Risque :** `str(e)` peut exposer : chemins de fichiers serveur, requêtes SQL internes, noms de variables, stack traces, messages d'erreur de base de données avec noms de tables/colonnes. Ces informations aident directement un attaquant à cartographier l'application.

**Correction recommandée :**
```python
except Exception as e:
    logger.exception("Erreur collecte %s", source_name)
    raise HTTPException(status_code=500, detail="internal error")
```
Réserver `str(e)` aux routes admin uniquement, et le tronquer :
```python
raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:100]}")
```

---

### 🟡 MOYEN — Multiples threads LLM spawnable sans limite — llm_routes.py:360-405

**Catégorie :** DoS / Resource exhaustion
**Code vulnérable :**
```python
@router.post("/run-background")
def run_background(request: Request, body: _RunBackgroundBody = _RunBackgroundBody()):
    _require_admin(request)
    # ...
    t = threading.Thread(target=_bg_process, args=(max_candidates,), daemon=True)
    t.start()
    return {"ok": True, ...}
```
**Risque :** Chaque appel à `/admin/llm/run-background` démarre un nouveau thread daemon **sans vérifier si un thread est déjà en cours**. N appels consécutifs créent N threads concurrents, tous effectuant des appels Anthropic API simultanément → rate limit Anthropic (429) en cascade, saturation du pool de connexions PostgreSQL (max_size=10), et mémoire illimitée.

**Correction recommandée :**
```python
import threading

_bg_thread: threading.Thread | None = None
_bg_lock = threading.Lock()

@router.post("/run-background")
def run_background(request: Request, ...):
    _require_admin(request)
    global _bg_thread
    with _bg_lock:
        if _bg_thread and _bg_thread.is_alive():
            raise HTTPException(409, "Un traitement est déjà en cours")
        _bg_thread = threading.Thread(target=_bg_process, args=(max_candidates,), daemon=True)
        _bg_thread.start()
    return {"ok": True, ...}
```

---

### 🟡 MOYEN — Absence de validation sur newsletter_frequency — portal_routes.py:726-728

**Catégorie :** Validation d'entrée / Logique métier
**Code vulnérable :**
```python
if payload.newsletter_frequency is not None:
    fields.append("newsletter_frequency = %s")
    values.append(payload.newsletter_frequency)
# Aucune validation de la valeur
```
**Risque :** Tout utilisateur authentifié peut injecter une chaîne arbitraire dans `newsletter_frequency` (ex. `"''; DROP TABLE users;--"` — sans risque d'injection SQL grâce aux paramètres préparés, mais stockage de valeurs arbitraires en base). Si ce champ est utilisé côté serveur pour conditionner un comportement (filtrage scheduler futur), une valeur inattendue peut causer un dysfonctionnement logique.

**Correction recommandée :**
```python
VALID_FREQUENCIES = {"monthly", "weekly", "daily"}
if payload.newsletter_frequency not in VALID_FREQUENCIES:
    raise HTTPException(400, f"Fréquence invalide. Valeurs : {VALID_FREQUENCIES}")
```

---

### 🟡 MOYEN — Email destinataire dans les query params — llm_routes.py:841

**Catégorie :** PII / Information Disclosure
**Code vulnérable :**
```python
@router.post("/newsletter/send-test")
def newsletter_send_test(
    request: Request,
    specialty: Optional[str] = Query(default=None),
    email: str = Query(description="Recipient email for test"),
):
```
**Risque :** Les query parameters sont loggés dans les access logs HTTP (Render, nginx, reverse proxies) et potentiellement dans les outils de monitoring. L'adresse email du destinataire du test (vraisemblablement un médecin ou l'admin) est exposée en clair dans les logs.

**Correction recommandée :**
```python
class SendTestBody(BaseModel):
    email: EmailStr
    specialty: Optional[str] = None

@router.post("/newsletter/send-test")
def newsletter_send_test(request: Request, body: SendTestBody):
    _require_admin(request)
    email = body.email
    specialty = body.specialty
```

---

### 🟡 MOYEN — /admin/llm/run-all bloque le worker indéfiniment — llm_routes.py:485-528

**Catégorie :** DoS / Availability
**Code vulnérable :**
```python
@router.post("/run-all")
def run_llm_all(request: Request, batch_size: int = ...):
    _require_admin(request)
    while True:
        candidates = _fetch_candidates_to_analyse(cur, None, batch_size)
        if not candidates:
            break
        for candidate in candidates:
            # Appel LLM synchrone — potentiellement des heures
            report = _process_one_candidate(candidate)
```
**Risque :** Cette route traite **tous** les candidats NEW dans une boucle `while True` **dans le même thread que la requête HTTP**. Avec 3 190 candidats (mentionnés dans les scripts), cela prendrait des heures, bloquant le worker Uvicorn entier (WEB_CONCURRENCY=1 sur Render). Le service devient inaccessible pour tous les autres utilisateurs.

**Correction recommandée :** Déléguer à `/admin/llm/run-background` pour tous les traitements longs. Ou ajouter un timeout HTTP explicite et utiliser BackgroundTasks de FastAPI.

---

### 🔵 FAIBLE — CSP avec 'unsafe-inline' — main.py:59-78

**Catégorie :** XSS / Headers de sécurité
**Code vulnérable :**
```python
"script-src 'self' 'unsafe-inline'; "
"style-src 'self' 'unsafe-inline'; "
```
**Risque :** `'unsafe-inline'` annule la protection contre les XSS que CSP est censée apporter. Si un vecteur XSS est découvert (template injection dans un article LLM, redirect ouvert, etc.), la CSP ne constitue aucune barrière supplémentaire.

**Correction recommandée :** Migrer vers des nonces ou hashes CSP :
```python
import secrets
nonce = secrets.token_urlsafe(16)
response.headers["Content-Security-Policy"] = (
    f"default-src 'self'; "
    f"script-src 'self' 'nonce-{nonce}'; "
    f"style-src 'self' 'nonce-{nonce}'; "
    # ...
)
# Injecter le nonce dans les <script> et <style> inline du HTML
```
Alternative court-terme : externaliser tous les scripts/styles inline en fichiers `.js`/`.css`.

---

### 🔵 FAIBLE — Absence de HSTS (Strict-Transport-Security) — main.py

**Catégorie :** Configuration TLS / Headers de sécurité
**Code vulnérable :**
```python
# SecurityHeadersMiddleware — HSTS absent
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
# ← pas de Strict-Transport-Security
```
**Risque :** Sans HSTS, un attaquant en position MITM peut downgrader une connexion HTTPS en HTTP lors du premier accès (attaque SSLStrip). Les tokens JWT et cookies d'authentification peuvent être interceptés.

**Correction recommandée :**
```python
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
```
Note : À ne pas activer avant de s'assurer que TLS est effectivement configuré (Render le gère automatiquement).

---

### 🔵 FAIBLE — Access token JWT stocké dans sessionStorage — portal.html:892, login.html:125

**Catégorie :** Stockage sensible côté client
**Code vulnérable :**
```javascript
sessionStorage.setItem('access_token', data.access_token);
// ...
function getToken() { return sessionStorage.getItem('access_token'); }
```
**Risque :** `sessionStorage` est accessible à tout JavaScript exécuté sur l'origine (y compris les scripts injectés par XSS). Le token JWT contient le claim `adm` qui détermine les droits admin. Sa fuite permet l'usurpation de session jusqu'à expiration (15 min par défaut).

Note positive : le pattern HttpOnly cookie + refresh token est bien implémenté. Le `sessionStorage` ne sert que pour l'access token de courte durée (15 min), ce qui limite l'exposition.

**Correction recommandée (long terme) :** Stocker l'access token dans une variable JS en mémoire uniquement (closure), sans persistance en storage. La rotation via refresh token HttpOnly est déjà en place.

---

### 🔵 FAIBLE — Rate limiter en mémoire non partagée (multi-worker) — security.py:169

**Catégorie :** Authentification / Rate limiting
**Code vulnérable :**
```python
_login_attempts: dict[str, collections.deque] = collections.defaultdict(collections.deque)
```
**Risque :** Le rate limiter est un dict Python en mémoire, par process. Si `WEB_CONCURRENCY > 1` (ou plusieurs instances Render), chaque worker a son propre compteur. Un attaquant avec N workers disponibles peut multiplier ses tentatives autorisées par N.

Note : Render force actuellement `WEB_CONCURRENCY=1`, ce qui rend le risque **acceptable aujourd'hui**. À surveiller si le scaling horizontal est activé.

**Correction recommandée (long terme) :** Utiliser Redis pour partager le compteur entre workers :
```python
import redis
r = redis.Redis(host=os.environ.get("REDIS_URL", "redis://localhost"))

def check_login_rate_limit(ip: str) -> None:
    key = f"login_attempts:{ip}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, _RATE_LIMIT_WINDOW)
    if count > _RATE_LIMIT_MAX:
        raise HTTPException(429, "Too many login attempts")
```

---

### 🔵 FAIBLE — Endpoint /users (signup) sans rate limiting — main.py:400-447

**Catégorie :** Enumération / DoS
**Code vulnérable :**
```python
@app.post("/users", status_code=201)
def create_user(payload: UserCreate):
    if not ALLOW_SIGNUP:
        raise HTTPException(status_code=403, detail="signup disabled")
    # Pas de check_login_rate_limit ici
    # ...
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="email already exists")
```
**Risque :** Quand `ALLOW_SIGNUP=true`, un attaquant peut :
1. **Énumérer les emails existants** via les réponses 201 (nouveau) vs 409 (existant) à vitesse illimitée.
2. **Saturer la DB** avec des inscriptions massives.
3. **Spammer via les emails de vérification** (un email par `POST /users`).

**Correction recommandée :**
```python
from app.security import check_login_rate_limit  # réutiliser ou créer un check dédié

@app.post("/users", status_code=201)
def create_user(payload: UserCreate, request: Request):
    check_signup_rate_limit(_real_ip(request))  # max 5/heure/IP
    # ...
```

---

### 🔵 FAIBLE — Email en clair dans les logs d'erreur send_bulk — mailer.py:184

**Catégorie :** PII / Information Disclosure
**Code vulnérable :**
```python
errors.append({"email": email, "error": result.error})
# L'adresse email complète est incluse dans le dict retourné par send_bulk
```
**Risque :** `send_bulk` retourne un dict `{"errors": [{"email": "...", "error": "..."}]}` qui pourrait être loggé ou exposé via une API admin. Les emails des abonnés (médecins) sont des données personnelles RGPD.

**Correction recommandée :**
```python
errors.append({
    "email_hash": hashlib.sha256(email.encode()).hexdigest()[:8],  # pour débogage
    "error": result.error
})
```

---

### 🔵 FAIBLE — Disclosure de l'email contact dans le User-Agent — web_scraper.py:37

**Catégorie :** Information Disclosure
**Code vulnérable :**
```python
_HEADERS = {
    "User-Agent": "MedNewsBot/1.0 (veille-reglementaire; contact@mednews.fr)",
```
**Risque :** L'adresse email `contact@mednews.fr` est visible dans les logs HTTP des sites scrapés (SFH, SFR, SFO, etc.). Elle peut être récoltée par des harvesters de spam.

**Correction recommandée :**
```python
"User-Agent": "MedNewsBot/1.0 (veille-reglementaire; https://mednews.fr)"
```

---

### 🔵 FAIBLE — Cache token PISTE non thread-safe — piste_client.py:8-64

**Catégorie :** Race condition
**Code vulnérable :**
```python
_TOKEN = {"value": None, "exp": 0}

def get_piste_token() -> str:
    if _TOKEN["value"] and now < _TOKEN["exp"] - 30:
        return _TOKEN["value"]  # lecture
    # ...
    _TOKEN["value"] = access_token  # écriture non atomique
    _TOKEN["exp"] = now + expires_in
```
**Risque :** En cas d'accès concurrent (scheduler + requête admin simultanés), deux threads peuvent dépasser le check `now < exp - 30` simultanément et effectuer deux refresh OAuth vers PISTE. Impact : 2 tokens générés, l'un écrase l'autre. Pas de vulnérabilité exploitable, mais double consommation de quota OAuth.

**Correction recommandée :**
```python
import threading
_TOKEN_LOCK = threading.Lock()

def get_piste_token() -> str:
    with _TOKEN_LOCK:
        if _TOKEN["value"] and now < _TOKEN["exp"] - 30:
            return _TOKEN["value"]
        # ... refresh ...
```

---

### ⚪ INFO — SHA-256 non salé pour email_lookup — main.py:226-227

**Catégorie :** Cryptographie
**Code vulnérable :**
```python
def email_lookup_hash(email_norm: str) -> bytes:
    return hashlib.sha256(email_norm.encode("utf-8")).digest()
```
**Risque :** Ce hash est utilisé pour la lookup déterministe en DB (conception volontaire). Cependant, une fuite de la table `users` permettrait une attaque par dictionnaire/rainbow tables sur les emails (les emails médicaux suivent des patterns prévisibles : `prenom.nom@hopital.fr`). Ce n'est pas une `injection` mais une `faiblesse de conception`.

Note : La protection principale est le chiffrement Fernet de `email_ciphertext`. Le `email_lookup` est un index de recherche, pas le stockage principal.

**Correction recommandée (long terme) :** Utiliser un HMAC avec une clé secrète dédiée :
```python
EMAIL_LOOKUP_SECRET = os.environ.get("EMAIL_LOOKUP_SECRET", "").encode()

def email_lookup_hash(email_norm: str) -> bytes:
    import hmac
    return hmac.new(EMAIL_LOOKUP_SECRET, email_norm.encode("utf-8"), "sha256").digest()
```

---

### ⚪ INFO — Vérification ADMIN_SECRET : vulnérabilité si secret vide — security.py:143-145

**Catégorie :** Authentification
**Code vulnérable :**
```python
expected = os.environ.get("ADMIN_SECRET")
got = request.headers.get("x-admin-secret")
if expected and got == expected:
    return
```
**Risque :** Si `ADMIN_SECRET=""` (chaîne vide), `if expected` est `False` et le check par secret est **entièrement skippé**, forçant l'utilisation du JWT. Ce comportement est documenté implicitement mais pas explicitement. Si un opérateur configure `ADMIN_SECRET=` (vide) en pensant désactiver l'accès admin, c'est l'inverse qui se produit.

**Correction recommandée :**
```python
expected = os.environ.get("ADMIN_SECRET", "").strip()
if not expected:
    logger.warning("ADMIN_SECRET non défini — accès admin uniquement via JWT")
```

---

### ⚪ INFO — Decode JWT manuel sans vérification (côté client) — shared.js:54

**Catégorie :** Info
**Code vulnérable :**
```javascript
var payload = JSON.parse(atob(token.split('.')[1]));
return !!payload.adm;
```
**Risque :** Ce decode client-side ne vérifie pas la signature JWT. Un utilisateur malveillant peut modifier le payload en base64 pour que `isAdmin()` retourne `true` et voir le lien `/review`. **Pas de risque serveur** car chaque route admin vérifie le JWT côté serveur. L'impact est purement cosmétique (affichage du lien review).

---

### ⚪ INFO — Pas de Permissions-Policy header — main.py

**Catégorie :** Headers de sécurité
**Risque :** Mineur. L'absence de `Permissions-Policy` laisse le navigateur accéder aux APIs sensibles (caméra, micro, géolocalisation) sans restriction depuis les pages du portail. Non pertinent pour une app purement textuelle, mais recommandé.

**Correction recommandée :**
```python
response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
```

---

### ⚪ INFO — Absence de Subresource Integrity (SRI) sur lucide.js — portal.html

**Catégorie :** Supply chain
**Code vulnérable :**
```html
<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
```
**Risque :** Chargement d'un CDN externe sans hash d'intégrité. Si `unpkg.com` est compromis ou si la version `@latest` change, du code malveillant peut être injecté. Impact limité par la CSP mais `'unsafe-inline'` réduit la protection.

**Correction recommandée :** Épingler la version + ajouter SRI :
```html
<script src="https://unpkg.com/lucide@0.344.0/dist/umd/lucide.min.js"
        integrity="sha384-[hash]" crossorigin="anonymous"></script>
```

---

## Tableau récapitulatif

| Sévérité | Nb | Fichiers concernés |
|---|---|---|
| 🔴 CRITIQUE | 0 | — |
| 🟠 ÉLEVÉ | 2 | `auth_routes.py`, `sources_routes.py` |
| 🟡 MOYEN | 5 | `auth_routes.py`, `sources_routes.py`, `main.py`, `portal_routes.py`, `llm_routes.py` |
| 🔵 FAIBLE | 8 | `security.py`, `main.py`, `mailer.py`, `web_scraper.py`, `piste_client.py`, `portal.html`, `login.html` |
| ⚪ INFO | 5 | `security.py`, `shared.js`, `main.py`, `portal.html` |
| **TOTAL** | **20** | |

---

## Points forts (ne pas casser)

Les éléments suivants sont **correctement implémentés** et constituent une base solide :

- ✅ **PBKDF2-SHA256 avec 100 000 itérations** et `secrets.compare_digest` (timing-safe)
- ✅ **JWT HS256** avec validation algo explicite (`algorithms=["HS256"]`), expiry 15 min
- ✅ **Refresh token rotation** avec `FOR UPDATE` (protection replay) et stockage haché (SHA256 + pepper)
- ✅ **CSRF double-submit** cookie + header avec `secrets.compare_digest`
- ✅ **SQL paramétré** partout — 0 interpolation de chaîne SQL visible
- ✅ **Chiffrement Fernet des emails** en base (AES-128-CBC avec IV aléatoire)
- ✅ **X-Content-Type-Options, X-Frame-Options, Referrer-Policy** présents
- ✅ **ALLOW_SIGNUP=false** par défaut (inscription désactivée)
- ✅ **Vérification d'email obligatoire** avant login
- ✅ **Logs PII réduits** (`email[:3] + "***"`) dans les erreurs d'envoi

---

## Top 5 Priorités

| Priorité | Vulnérabilité | Effort | Impact si non corrigé |
|---|---|---|---|
| **1** | 🟠 Rate limiting IP bypass (proxy) | **1h** | Brute-force illimité sur les comptes médecins |
| **2** | 🟡 Timing oracle email enumeration | **30min** | Enumération de tous les comptes inscrits |
| **3** | 🟡 Exception exposure `str(e)` | **30min** | Fuite d'architecture interne à chaque erreur serveur |
| **4** | 🟠 SSRF `/admin/sources/test-feed` | **1h** | Accès aux métadonnées cloud si compte admin compromis |
| **5** | 🔵 HSTS manquant | **5min** | Downgrade TLS possible sur premier accès |

**Effort total estimé pour le Top 5 : ~3h30**

---

*Rapport généré le 2026-03-25 — Révision recommandée après chaque ajout de route ou de dépendance.*
