# Audit Autorisation & IDOR — MedNews Backend
**Date :** 2026-03-25
**Scope :** app/auth_routes.py · app/llm_routes.py · app/piste_routes.py · app/sources_routes.py · app/portal_routes.py · app/main.py · app/db.py · app/security.py
**Méthode :** Lecture ligne par ligne de chaque handler — traçage JWT → SQL → WHERE clause
**Auditeur :** Claude Sonnet 4.6

---

## Résumé exécutif

**Bonne nouvelle : aucun vrai IDOR entre utilisateurs.**
Toutes les données privées (profil, favoris, préférences) sont systématiquement filtrées par `user_id` extrait du JWT — jamais par un paramètre de requête contrôlable par le client. La séparation admin / user est correctement implémentée via `require_admin`.

Trois findings de logique d'accès (non-IDOR) méritent attention.

---

## Findings

---

### 🟡 MOYEN — Audience clause incomplète dans `GET /articles/{item_id}` — portal_routes.py:364

**Catégorie :** Incohérence list/detail — access control logique

**Scénario d'attaque :**
Un utilisateur avec `specialty = 'pharmacien'` appelle `GET /articles` et voit correctement les articles dont `type_praticien = 'prescripteur'` (clause OR dans `_build_audience_clause`). Il clique sur l'un de ces articles → `GET /articles/{item_id}` → **404**, car le détail utilise une clause simplifiée qui exclut le critère `type_praticien`.

En pratique : l'utilisateur arrive sur un article présent dans sa liste mais ne peut pas l'ouvrir. Ce bug d'UX est aussi un contournement inverse : un utilisateur `specialty = 'medecine-generale'` peut lister les articles d'une autre spécialité via `?specialty=cardiologie` mais ne peut pas accéder à leur détail (404), rendant le filtre de liste inutile.

**Code vulnérable — liste (correct) :**
```python
# portal_routes.py:120-133
def _build_audience_clause(audience, slug):
    if slug == "pharmacien":
        return (
            "(i.audience = 'PHARMACIENS'"
            " OR i.specialty_slug = 'pharmacien'"
            " OR i.type_praticien = 'prescripteur')",
            (),
        )
    elif slug:
        return "i.specialty_slug = %s", (slug,)
```

**Code vulnérable — détail (incomplet) :**
```python
# portal_routes.py:364-373
cur.execute("""
    SELECT ...
    FROM items i JOIN candidates c ON c.id = i.candidate_id
    WHERE i.id = %s
      AND i.review_status = 'APPROVED'
      AND (%s IS NULL OR i.specialty_slug = %s);   ← clause simpliste, ignore audience et type_praticien
""", (item_id, slug, slug))
```

**Impact secondaire :** Si `slug = None` (utilisateur sans spécialité), la condition `(NULL IS NULL OR ...)` est `TRUE` — accès illimité à tous les articles APPROVED, toutes spécialités. Probablement intentionnel (onboarding) mais non documenté.

**Correction recommandée :**
```python
# Réutiliser _build_audience_clause dans le détail
aud_clause, aud_params = _build_audience_clause(None, slug)
cur.execute(f"""
    SELECT ...
    FROM items i JOIN candidates c ON c.id = i.candidate_id
    WHERE i.id = %s
      AND i.review_status = 'APPROVED'
      AND {aud_clause};
""", (item_id, *aud_params))
```

---

### 🔵 FAIBLE — Réassignation de spécialité sans validation métier — portal_routes.py:670

**Catégorie :** Logique d'accès / escalade de contenu

**Scénario d'attaque :**
N'importe quel utilisateur authentifié peut appeler :
```http
PATCH /me/specialty
{"specialty_slug": "pharmacien"}
```
…et voir immédiatement les articles ciblés pharmaciens, y compris les articles `type_praticien = 'prescripteur'` de toutes les spécialités prescriptrices.

Si le modèle économique futur repose sur un abonnement par spécialité, un utilisateur pourrait contourner la segmentation tarifaire.

**Code vulnérable :**
```python
# portal_routes.py:670-681
@router.patch("/me/specialty")
def update_specialty(payload: SpecialtyUpdate, user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug FROM specialties WHERE slug = %s;", (payload.specialty_slug,))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="specialty not found")
            cur.execute(
                "UPDATE users SET specialty_id = %s WHERE id = %s;",
                (payload.specialty_slug, user_id),   # ← aucune vérification de cohérence métier
            )
```

**Note :** La route est correctement scopée (WHERE id = user_id depuis JWT — pas d'IDOR). Le seul problème est l'absence de contrôle métier sur la valeur choisie.

**Correction recommandée (si modèle tarifaire à venir) :**
```python
# Vérifier que la spécialité fait partie des spécialités autorisées pour cet utilisateur
# (ex. via une table user_allowed_specialties ou un champ subscription_plan)
RESTRICTED_SLUGS = set()  # à alimenter si abonnements différenciés

if payload.specialty_slug in RESTRICTED_SLUGS:
    cur.execute("SELECT 1 FROM user_subscriptions WHERE user_id = %s AND slug = %s",
                (user_id, payload.specialty_slug))
    if not cur.fetchone():
        raise HTTPException(403, "specialty not included in your subscription")
```

---

### 🔵 FAIBLE — `POST /favorites/{item_id}` sans validation d'existence de l'item — portal_routes.py:414

**Catégorie :** Validation d'entrée / intégrité référentielle

**Scénario d'attaque :**
Un utilisateur peut insérer un favori pointant vers un UUID inexistant, un item PENDING ou REJECTED :
```http
POST /favorites/00000000-0000-0000-0000-000000000000
```
Aucune vérification que l'item existe ET est APPROVED. Résultat : favoris orphelins en base, et `GET /favorites` retourne des IDs qui renvoient 404 si on les consulte.

**Code vulnérable :**
```python
# portal_routes.py:414-426
@router.post("/favorites/{item_id}")
def add_favorite(item_id: str, user_id: str = Depends(_get_current_user_id)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO favorites (user_id, item_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
                (user_id, item_id),   # ← pas de vérification que item_id existe et est APPROVED
            )
    return {"status": "added"}
```

**Note :** Pas d'IDOR — le `user_id` est correctement issu du JWT. L'ownership est bien respecté. C'est uniquement une validation d'entrée manquante.

**Correction recommandée :**
```python
# Vérifier que l'item existe et est APPROVED avant d'insérer
cur.execute(
    "SELECT id FROM items WHERE id = %s AND review_status = 'APPROVED';",
    (item_id,)
)
if not cur.fetchone():
    raise HTTPException(status_code=404, detail="article not found")
cur.execute("INSERT INTO favorites (user_id, item_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            (user_id, item_id))
```

---

### ⚪ INFO — `GET /_version` expose le hash git sans authentification — main.py:451

**Catégorie :** Information Disclosure

**Code :**
```python
@app.get("/_version")
def version():
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}
```

**Risque :** Le hash de commit permet à un attaquant de savoir exactement quelle version est déployée, de comparer avec le dépôt public pour cibler des vulnérabilités connues non encore patchées. Impact faible si le dépôt est privé.

**Correction :**
```python
@app.get("/_version")
def version(request: Request):
    _require_secret(request, "x-admin-secret", ADMIN_SECRET)
    return {"commit": os.environ.get("RENDER_GIT_COMMIT", "unknown")}
```

---

### ⚪ INFO — Browsing cross-spécialité par design non documenté — portal_routes.py:136

**Catégorie :** Logique d'accès (documentation)

**Observation :**
Le paramètre `?specialty=<slug>` dans `GET /articles`, `GET /articles/months` accepte **n'importe quelle spécialité**, permettant à tout utilisateur authentifié de voir les articles de n'importe quelle spécialité :

```python
slug = specialty if specialty else _get_user_specialty_slug(user_id)
```

Ce comportement semble **intentionnel** (veille multi-spécialité), mais il n'est pas documenté et crée une incohérence avec le détail d'article (voir finding MOYEN ci-dessus).

**Recommandation :** Documenter explicitement ce choix dans un commentaire de code. Si l'accès multi-spécialité doit être restreint à l'avenir, le contrôle doit être ajouté ici.

---

## Points forts — ce qui est correctement implémenté

| Mécanisme | Détail |
|---|---|
| ✅ **JWT sub non falsifiable** | `user_id = payload.get("sub")` — jamais lu depuis le body ou les query params |
| ✅ **GET /me** | `WHERE u.id = %s` avec user_id JWT — impossible d'accéder au profil d'un autre user |
| ✅ **GET /favorites** | `WHERE user_id = %s` avec JWT — isolation parfaite |
| ✅ **DELETE /favorites/{item_id}** | `WHERE user_id = %s AND item_id = %s` — impossible de supprimer le favori d'un autre user |
| ✅ **PATCH /me/specialty** | `WHERE id = %s` JWT — impossible de modifier la spécialité d'un autre user |
| ✅ **PATCH /me/preferences** | `WHERE id = %s` JWT — idem |
| ✅ **POST /auth/resend-verification** | Scopé au JWT — impossible de déclencher pour un autre compte |
| ✅ **Refresh token rotation** | `FOR UPDATE` + token haché — impossible de voler la session d'un autre user |
| ✅ **Séparation admin/user** | `require_admin` sur toutes les routes `/admin/*` — pas de privilege escalation possible via JWT user |
| ✅ **Pas d'ID user dans le body** | Aucune route n'accepte un `user_id` dans le body qu'elle utiliserait directement en SQL sans vérification JWT |

---

## Tableau récapitulatif de tous les endpoints

| Endpoint | Auth requise | Ownership vérifié | Verdict |
|---|---|---|---|
| `POST /auth/login` | ❌ (public) | N/A | ✅ Safe |
| `POST /auth/refresh` | Cookie + CSRF | N/A (token hash) | ✅ Safe |
| `POST /auth/logout` | Cookie + CSRF | N/A (token hash) | ✅ Safe |
| `POST /auth/verify-email` | ❌ (public) | Token 256 bits | ✅ Safe |
| `POST /auth/resend-verification` | ✅ JWT | ✅ WHERE id = JWT | ✅ Safe |
| `GET /me` | ✅ JWT | ✅ WHERE id = JWT | ✅ Safe |
| `PATCH /me/specialty` | ✅ JWT | ✅ WHERE id = JWT | 🔵 Logique métier |
| `GET /me/preferences` | ✅ JWT | ✅ WHERE id = JWT | ✅ Safe |
| `PATCH /me/preferences` | ✅ JWT | ✅ WHERE id = JWT | ✅ Safe |
| `GET /articles` | ✅ JWT | ⚠️ Cross-specialty by design | ⚪ Info |
| `GET /articles/counts` | ✅ JWT | N/A (agrégat) | ✅ Safe |
| `GET /articles/months` | ✅ JWT | ⚠️ Cross-specialty by design | ⚪ Info |
| `GET /articles/{item_id}` | ✅ JWT | ⚠️ Clause incomplète (pharmacien) | 🟡 Moyen |
| `GET /favorites` | ✅ JWT | ✅ WHERE user_id = JWT | ✅ Safe |
| `POST /favorites/{item_id}` | ✅ JWT | ✅ user_id = JWT (mais item non validé) | 🔵 Faible |
| `DELETE /favorites/{item_id}` | ✅ JWT | ✅ WHERE user_id = JWT AND item_id | ✅ Safe |
| `GET /specialties` | ❌ (public) | N/A | ✅ Safe |
| `POST /users` | ❌ (signup, ALLOW_SIGNUP flag) | N/A | ✅ Safe |
| `GET /health` | ❌ (public) | N/A | ✅ Safe |
| `GET /health/db` | ❌ (public) | N/A | ✅ Safe |
| `GET /_version` | ❌ (public) | N/A | ⚪ Info |
| `POST /admin/init-db` | ✅ x-init-secret | N/A | ✅ Safe |
| `POST /admin/migrate` | ✅ x-migrate-secret | N/A | ✅ Safe |
| `POST /admin/scheduler/run-collect` | ✅ x-admin-secret | N/A | ✅ Safe |
| `POST /admin/scheduler/run-send` | ✅ x-admin-secret | N/A | ✅ Safe |
| `POST /admin/test-email` | ✅ x-admin-secret | N/A | ✅ Safe |
| `GET /admin/llm/stats` | ✅ admin | N/A | ✅ Safe |
| `GET /admin/llm/pending` | ✅ admin | N/A | ✅ Safe |
| `GET /admin/llm/items` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/run` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/run-all` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/run-background` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/pre-filter` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/reset-all` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/review/{item_id}` | ✅ admin | N/A (admin scope) | ✅ Safe |
| `POST /admin/llm/newsletter/preview` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/llm/newsletter/send-test` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/jorf/last-7-days` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/jorf/debug-sample` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/jorf/search-sample` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/jorf/search-debug` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/jorf/search-to-candidates` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/piste/collect-extra` | ✅ admin | N/A | ✅ Safe |
| `GET /admin/sources/status` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/jorf` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/kali` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/has` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/ansm` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/spf` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/web` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/all` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/collect/pratique` | ✅ admin | N/A | ✅ Safe |
| `POST /admin/sources/test-feed` | ✅ admin | N/A | ✅ Safe (SSRF fixé) |

---

## Tableau récapitulatif des findings

| Sévérité | Nb | Endpoints concernés |
|---|---|---|
| 🔴 CRITIQUE | 0 | — |
| 🟠 ÉLEVÉ | 0 | — |
| 🟡 MOYEN | 1 | `GET /articles/{item_id}` |
| 🔵 FAIBLE | 2 | `PATCH /me/specialty`, `POST /favorites/{item_id}` |
| ⚪ INFO | 2 | `GET /_version`, `GET /articles?specialty=X` |
| **TOTAL** | **5** | |

---

## Conclusion

L'architecture d'autorisation est saine. Le pattern `user_id = Depends(_get_current_user_id)` isole systématiquement les données par utilisateur, et aucune route ne lit un `user_id` depuis le body ou les query params sans le valider contre le JWT. Il n'existe **aucun vrai IDOR** permettant à l'utilisateur A d'accéder aux données privées de l'utilisateur B.

Le seul finding actionnable à court terme est le **finding MOYEN** (clause audience incomplète dans le détail d'article) qui cause un bug UX pour les pharmaciens et une incohérence list/detail.

*Audit réalisé le 2026-03-25 — Révision recommandée si de nouveaux endpoints portail sont ajoutés.*
