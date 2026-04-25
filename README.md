# Med Newsletter — Backend

Newsletter réglementaire mensuelle pour médecins, personnalisée par spécialité.
Pipeline **100% manuel** — collecte et analyse déclenchées à la demande, envoi sur validation.

## Architecture

```
med-news-back/
├── app/
│   ├── main.py               # FastAPI + routes admin
│   ├── collector.py          # Orchestration collecte (RSS + PubMed + Web + API)
│   ├── rss_collector.py      # Collecte RSS (sociétés savantes, HAS, ANSM, EMA…)
│   ├── pubmed_collector.py   # Collecte PubMed via API NCBI
│   ├── web_scraper.py        # Scraping HTML (HAS, ESVS…)
│   ├── piste_collector.py    # Collecte JORF via API PISTE / Légifrance
│   ├── sources.py            # ALL_FEEDS + API_SOURCES (catalogue complet)
│   ├── llm_analysis.py       # Prompt + scoring Claude par spécialité
│   ├── llm_routes.py         # Routes review (PENDING → APPROVED)
│   ├── newsletter_builder.py # Génération HTML email par spécialité
│   ├── mailer.py             # Envoi SendGrid ou SMTP
│   ├── auth_routes.py        # Login / logout / refresh token
│   ├── db.py                 # Connexion PostgreSQL
│   ├── security.py           # JWT, PBKDF2, CSRF
│   └── migrations.py         # Migrations SQL
├── scripts/
│   ├── pipeline.py           # CLI principal : collect / prefilter / llm
│   ├── feeds_test.py         # Dry-run RSS (0 DB, 0 LLM)
│   ├── feeds_discover.py     # Scanner de nouveaux flux RSS
│   ├── pentest.py            # Tests d'intrusion cross-utilisateur
│   └── reset_admin.py        # Reset email/mot de passe admin
├── sql/
│   ├── 010_pipeline_candidates_items.sql
│   └── 020_specialties_seed.sql
├── .env.example
└── requirements.txt
```

## Installation locale

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Remplir .env : DATABASE_URL, ANTHROPIC_API_KEY, ADMIN_SECRET…

uvicorn app.main:app --reload
```

## Pipeline manuel (spécialité par spécialité)

Le pipeline se lance depuis la racine du projet via `scripts/pipeline.py`.

### Workflow par spécialité

```bash
# 1. Collecte — fenêtre 180 jours, sources filtrées par spécialité + sources "tous"
python3 scripts/pipeline.py collect --specialty cardiologie --days 180

# 2. Pré-filtre — élimine les candidats hors-scope sans appel LLM
# --specialty active le filtre par mots-clés sur les 28 sources "tous"
python3 scripts/pipeline.py prefilter --specialty cardiologie

# 3. Analyse LLM — Claude score et classe tous les candidats NEW
python3 scripts/pipeline.py llm
```

### Collecte globale (toutes spécialités)

```bash
python3 scripts/pipeline.py collect --all --days 180
python3 scripts/pipeline.py prefilter  # sans --specialty : traite toutes spécialités, pas de filtre mot-clé
python3 scripts/pipeline.py llm
```

### Options utiles

```bash
# Tester le prefilter sans écrire en base
python3 scripts/pipeline.py prefilter --dry-run

# Limiter le LLM à N candidats (test ou quota API)
python3 scripts/pipeline.py llm --limit 50
```

### Spécialités disponibles

```
anesthesiologie      biologiste           cardiologie
chirurgie-cardiaque  chirurgie-orthopedique  chirurgie-pediatrique
chirurgie-plastique  chirurgie-thoracique  chirurgie-vasculaire
dentiste             dermatologie         endocrinologie
gastro-enterologie   geriatrie            gynecologie
hematologie          infectiologie        infirmiers
kinesitherapie       medecine-generale    medecine-interne
medecine-physique    medecine-urgences    nephrologie
neurochirurgie       neurologie           oncologie
ophtalmologie        orl                  pediatrie
pharmacien           pneumologie          psychiatrie
radiologie           rhumatologie         sage-femme
urologie
```

## Interface de review

Ouvrir `med-news-front/review.html` dans un navigateur.
Entrer l'URL du backend + la clé admin → les articles PENDING s'affichent
triés par score d'importance. Cliquer Approuver / Rejeter.

## Envoi newsletter

```bash
# Preview HTML avant envoi
curl -X POST https://mon-app.onrender.com/admin/llm/newsletter/preview \
  -H "x-admin-secret: MON_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"specialty_slug": "cardiologie"}'

# Envoi test (destinataire unique)
curl -X POST https://mon-app.onrender.com/admin/llm/newsletter/send-test \
  -H "x-admin-secret: MON_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"specialty_slug": "cardiologie", "email": "test@example.com"}'

# Envoi production (tous les abonnés de la spécialité)
curl -X POST https://mon-app.onrender.com/admin/llm/newsletter/send-all \
  -H "x-admin-secret: MON_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"specialty_slug": "cardiologie"}'
```

## Scripts utilitaires

```bash
# Tester les feeds RSS actifs (dry-run, 0 DB)
python3 scripts/feeds_test.py
python3 scripts/feeds_test.py --sources cnge,sfhta --days 30 --show-dropped

# Scanner de nouveaux flux RSS sociétés savantes
export ADMIN_SECRET=xxx
python3 scripts/feeds_discover.py

# Tests d'intrusion cross-utilisateur
export ADMIN_SECRET=xxx
python3 scripts/pentest.py https://mon-app.onrender.com

# Reset admin (email ou mot de passe)
python3 scripts/reset_admin.py
```

## Variables d'environnement

| Variable | Description |
|---|---|
| `DATABASE_URL` | URL PostgreSQL (Neon) |
| `ANTHROPIC_API_KEY` | Clé Claude (Haiku 4.5) |
| `SENDGRID_API_KEY` | Clé SendGrid (ou configurer `SMTP_*`) |
| `ADMIN_SECRET` | Protège toutes les routes `/admin/*` |
| `PISTE_CLIENT_ID` / `PISTE_CLIENT_SECRET` | Accès API Légifrance (JORF) |
| `BASE_URL` | URL publique du service (utilisée dans les emails) |
| `SCHEDULER_ENABLED` | `true` pour activer le scheduler APScheduler (non utilisé actuellement) |
| `MEDNEWS_BASE_URL` | URL backend pour `feeds_discover.py` (défaut: URL Render) |
