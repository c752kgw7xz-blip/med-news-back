# Med Newsletter — Backend

Newsletter réglementaire mensuelle pour médecins, tailored par spécialité.
**Entièrement automatique** — zéro intervention sauf la validation du contenu.

## Architecture

```
med-news-back/
├── app/
│   ├── main.py               # FastAPI + routes admin + scheduler branché
│   ├── scheduler.py          # Automatisation mensuelle (APScheduler)
│   ├── llm_analysis.py       # Scoring Claude par spécialité
│   ├── llm_routes.py         # Routes review (PENDING→APPROVED)
│   ├── newsletter_builder.py # Génération HTML email par spécialité
│   ├── mailer.py             # Envoi SendGrid ou SMTP
│   ├── piste_client.py       # OAuth2 Légifrance (PISTE)
│   ├── piste_routes.py       # Collecte JORF → candidates
│   ├── auth_routes.py        # Login / logout / refresh token
│   ├── db.py                 # Connexion PostgreSQL
│   ├── security.py           # JWT, PBKDF2, CSRF
│   └── migrations.py         # Migrations SQL
├── sql/
│   ├── 010_pipeline_candidates_items.sql
│   └── 020_specialties_seed.sql
├── .env.example
├── requirements.txt
└── requirements-crawler.txt
```

## Installation locale

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Remplir .env : DATABASE_URL, ANTHROPIC_API_KEY, ADMIN_SECRET…

uvicorn app.main:app --reload
```

## Pipeline automatique

Le scheduler tourne dans le même process que l'API.
Il se déclenche automatiquement deux fois par mois :

```
Jour 1  06h UTC  → Collecte JORF + Analyse Claude (tous les candidats NEW)
Jour 7  08h UTC  → Envoi newsletter (articles APPROVED uniquement)
```

**Activer le scheduler :**
```
SCHEDULER_ENABLED=true dans .env
```

## Déclenchement manuel (pour tester)

```bash
# Lancer la collecte + analyse LLM maintenant
curl -X POST http://localhost:8000/admin/scheduler/run-collect \
  -H "x-admin-secret: MON_SECRET"

# Lancer l'envoi des newsletters maintenant
curl -X POST http://localhost:8000/admin/scheduler/run-send \
  -H "x-admin-secret: MON_SECRET"
```

## Interface de review

Ouvrir `med-news-front/review.html` dans un navigateur.
Entrer l'URL du backend + la clé admin → les articles PENDING s'affichent
triés par score d'importance. Cliquer Approuver / Rejeter.

## Variables d'environnement clés

| Variable | Description |
|---|---|
| `DATABASE_URL` | URL PostgreSQL |
| `ANTHROPIC_API_KEY` | Clé Claude |
| `SENDGRID_API_KEY` | Clé SendGrid (ou configurer SMTP_*) |
| `ADMIN_SECRET` | Protège toutes les routes /admin/* |
| `SCHEDULER_ENABLED` | `true` pour activer l'automatisation |
| `PISTE_CLIENT_ID/SECRET` | Accès API Légifrance |
| `BASE_URL` | URL publique du service (ex: `https://mon-app.onrender.com`), utilisée dans les emails de vérification |
