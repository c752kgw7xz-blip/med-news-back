# CLAUDE.md — Règles invariables MedNews Backend

> Ces règles s'appliquent à TOUTES les sessions, TOUTES les spécialités, SANS EXCEPTION.
> "Hardcodées" par l'utilisateur après répétitions multiples. Ne pas reformuler, ne pas oublier.

---

## 🔴 RÈGLE 0 — "lance X" : date de dernière collecte CIBLÉE = point de départ obligatoire

Avant tout triage, vérifier la date de la **dernière collecte ciblée** pour la spécialité.

**Collecte ciblée = sources spécifiques à la spécialité uniquement.**
Les articles ajoutés en cross-spé (depuis NEJM, ANSM, JORF, Lancet généraliste, HAS…) ne comptent PAS — ces sources sont partagées entre toutes les spécialités.

```sql
-- Remplacer par les sources SPÉCIFIQUES à la spécialité (ex. pubmed_gut, bmj_gut pour gastro)
SELECT MAX(created_at) FROM candidates
WHERE source IN ('source_spé_1', 'source_spé_2', ...)
  AND status != 'NEW';
```

- **Date trouvée** → la nouvelle collecte couvre depuis cette date jusqu'à aujourd'hui
- **Aucune source jamais collectée** → collecter sur **120 jours en arrière**
- **Afficher dans la réponse** : *"Dernière collecte ciblée : JJ/MM/AAAA — fenêtre : JJ/MM/AAAA → aujourd'hui"*

Ne jamais supposer la fenêtre de collecte. Toujours la calculer sur les sources ciblées.

---

## 🔴 PROTOCOLE "lance X" — Exécuter dans l'ordre, sans exception

### Étape 0 — Date de dernière collecte CIBLÉE
Sources ciblées = sources spécifiques à la spé (pas NEJM/ANSM/JORF/HAS/Lancet généraliste qui sont cross-spé).
```sql
SELECT MAX(created_at) FROM candidates
WHERE source IN ('source_spé_1', 'source_spé_2', ...) AND status != 'NEW';
```
- Date trouvée → nouvelle collecte depuis cette date jusqu'à aujourd'hui
- Jamais collecté → 120 jours en arrière
- Afficher : *"Dernière collecte ciblée : JJ/MM/AAAA — fenêtre : JJ/MM/AAAA → aujourd'hui"*

### Étape 1 — Lire llm_analysis.py
Lire le SYSTEM_PROMPT complet + l'addendum `_SPECIALTY_ADDENDUM_X` en entier.

### Étape 2 — Lire 3 items vasculaires APPROVED (référence qualité)
```sql
SELECT tri_json->>'titre_court', tri_json->>'resume', tri_json->>'impact_pratique'
FROM items WHERE specialty_slug='chirurgie-vasculaire' AND review_status='APPROVED'
ORDER BY created_at DESC LIMIT 3;
```

### Étape 3 — Scan et réévaluation des items existants pour la spé
```sql
SELECT id, source_type, review_status, tri_json->>'titre_court',
       tri_json->>'resume', tri_json->>'impact_pratique'
FROM items WHERE specialty_slug='<slug>' AND review_status IN ('APPROVED','PENDING')
ORDER BY source_type, created_at;
```
Réévaluer avec les critères actuels. Passer en REJECTED ce qui échoue. Réécrire le ton si résumé ouvre sur la méthode. Ne démarrer le triage de nouveaux candidats qu'une fois terminé.

### Étape 4 — Triage des candidats NEW + liste cross-spé en temps réel
Filtre praticien ~15-20%. Scanner impérativement les sources réglementaires ET recommandations (voir RÈGLE 2) en plus des sources spécialisées.

**OBLIGATOIRE pendant le triage :** tenir une liste cross-spé au fil de la lecture. Dès qu'un article issu d'une source spécifique à la spé X relève en réalité d'une autre spécialité Y, l'ajouter immédiatement à la liste :

```
LISTE CROSS-SPÉ (construite article par article pendant le triage) :
| titre | source | spécialité cible |
|---|---|---|
| ... | pubmed_xxx | cardiologie |
| ... | pubmed_yyy | endocrinologie |
```

Ne pas attendre la fin du triage pour constituer cette liste. Ne jamais "passer à l'étape suivante" sans l'avoir complétée.

### Étape 4bis — Insertion cross-spé (AVANT les Q1-Q5)
Traiter et insérer les articles de la liste cross-spé construite à l'étape 4, avec **autant de rigueur** que les articles de la spé principale :
- Même filtre praticien strict (~15-20%)
- Même ton : phrase 1 = résultat chiffré
- Même structure JSON (tri_json + lecture_json)
- INSERT avec le bon `specialty_slug` de la spé cible
- UPDATE candidates SET status='LLM_DONE'

Si la liste cross-spé est vide après le triage, le noter explicitement : *"Liste cross-spé : aucun article identifié."*

### Étape 4ter — Articles médecin libéral (TRANSVERSAL_LIBERAL) — pendant tout triage

**Sources médecin libéral** : `cnom`, `ameli_medecin`, `carmf`, `csmf`, `mgfrance`

Ces sources apparaissent systématiquement dans les candidates disponibles. Pendant tout triage d'une spécialité, identifier les articles issus de ces 5 sources et les insérer avec :
- `audience = 'TRANSVERSAL_LIBERAL'`
- `specialty_slug = NULL`
- `categorie = 'exercice'` (sauf exception : drug/dispositif → `therapeutique`, pratique clinique → `clinique`)

Ces articles sont **automatiquement injectés dans le feed de toutes les spécialités** par `portal_routes.py` (`_build_audience_clause` inclut `OR i.audience = 'TRANSVERSAL_LIBERAL'`). Pas de traitement UI spécial.

Template INSERT TRANSVERSAL_LIBERAL :
```python
cur.execute("""
    INSERT INTO items (id, candidate_id, audience, specialty_slug, tri_json, lecture_json,
                       review_status, categorie, source_type, score_density, llm_created_at, created_at)
    VALUES (%s, %s, 'TRANSVERSAL_LIBERAL', NULL, %s, %s, 'PENDING', %s, %s, 7, NOW(), NOW())
    ON CONFLICT DO NOTHING
""", (str(uuid.uuid4()), cand_id, tri, lect, categorie, source_type))
```

Si aucun article médecin libéral trouvé dans le lot → noter explicitement : *"TRANSVERSAL_LIBERAL : aucun article identifié."*

### Étape 5 — Insertion spécialité principale (voir RÈGLE 1, 3, 4)
Checklist A-F avant chaque INSERT (structure JSON, ton, score_density=7).

### Étape 6 — Checklist post-insertion (voir RÈGLES 1-6)
Exécuter et afficher dans la réponse pour la spécialité traitée uniquement :
- **A** Structure JSON exacte (titre_court, texte_long, points_cles — champs interdits)
- **B** Sources réglementaires ET recommandations (tableau yields — reglementaire=0 ou recommandation=0 → AGIR)
- **C** Ton : phrase 1 = résultat chiffré, auto-contrôle
- **D** Template psycopg2 avec score_density=7
- **E** Filtre praticien ~15-20%
- **F** Stats Q1 affichées en tableau + actions si répartition anormale (relancer collecte, ajouter sources)

### Étape 7 — Correction type_praticien (OBLIGATOIRE pour les spécialités prescriptrices)

**Applicable si la spécialité est dans `_PRESCRIPTEUR_SLUGS`** (`portal_routes.py`) :
`medecine-generale`, `cardiologie`, `dermatologie`, `endocrinologie`, `gastro-enterologie`, **`gynecologie`**, `neurologie`, `ophtalmologie`, `orl`, `pediatrie`, `pneumologie`, `psychiatrie`, `rhumatologie`, `urologie`, `medecine-interne`, `medecine-urgences`, `geriatrie`, `medecine-physique`, `oncologie`, `hematologie`, `infectiologie`, `nephrologie`, `radiologie`

Le portail applique `(type_praticien IS NULL OR type_praticien != 'interventionnel')` pour ces spécialités. Le LLM tague souvent les alertes matériovigilance (da Vinci, bistouri, ventouse…) comme `interventionnel` → invisibles sur le portail même pour des praticiens qui utilisent ces dispositifs.

**Fix obligatoire après chaque lot inséré :**
```python
# Tous les réglementaires → NULL (alertes matériovigilance/JORF visibles à tous)
cur.execute("""
    UPDATE items SET type_praticien = NULL
    WHERE specialty_slug = %s
      AND source_type = 'reglementaire'
      AND type_praticien IS NOT NULL
""", (slug,))

# Recommandations interventionnelles légitimes pour la spé → NULL
cur.execute("""
    UPDATE items SET type_praticien = NULL
    WHERE specialty_slug = %s
      AND source_type = 'recommandation'
      AND type_praticien = 'interventionnel'
""", (slug,))
conn.commit()
```

**Vérification portail (mois courant) :**
```sql
SELECT COALESCE(source_type,'innovation'), COUNT(DISTINCT i.candidate_id)
FROM items i JOIN candidates c ON c.id = i.candidate_id
WHERE i.review_status = 'APPROVED'
  AND COALESCE(i.score_density, 0) >= 3
  AND i.specialty_slug = '<slug>'
  AND (i.type_praticien IS NULL OR i.type_praticien != 'interventionnel')
GROUP BY 1;
```
→ **Si reglementaire = 0 après le fix : investiguer** (items manquants ou official_date hors fenêtre).

---

## 🔴 RÈGLE 1 — Structure JSON obligatoire à chaque INSERT (bug récurrent numéro 1 & 2)

`review.html` et `newsletter_builder.py` lisent des champs exacts. Tout nom différent = zone vide dans l'UI.

### `tri_json` — champs EXACTS :
```python
tri = json.dumps({
    "titre_court": "...",        # ≤ 12 mots — JAMAIS "titre"
    "resume": "...",             # résultat en phrase 1, chiffres intégrés
    "impact_pratique": "...",    # "En pratique : ..." ou "À retenir : ..."
    "nature": "META-ANALYSE",   # META-ANALYSE | ETUDE | RECOMMANDATION | ALERTE | ARRETE
    "date_publication": "YYYY-MM-DD"
})
```

### `lecture_json` — champs EXACTS :
```python
lect = json.dumps({
    "texte_long": "...",         # Analyse détaillée (section "Analyse" dans review.html)
    "points_cles": [             # 2-3 bullets (section "Points clés" dans review.html)
        "Résultat principal avec chiffres clés",
        "Design : type étude, N, population",
        "Limite ou nuance clinique principale"
    ]
})
```

**INTERDIT dans tri_json :** `titre`, `source`, `lien`
**INTERDIT dans lecture_json :** `design`, `population`, `intervention`, `comparateur`, `resultats_principaux`, `limites`, `reference_complete`

**score_density = 7** dans tout INSERT. NULL = invisible dans review.html.

### Nomenclature portail — à retenir absolument

| Niveau | Colonne DB | Valeurs | Affiché portail |
|---|---|---|---|
| **Catégorie** | `source_type` | `reglementaire` / `recommandation` / `innovation` | Pills horizontaux : Réglementation / Recommandation / Innovation |
| **Sous-catégorie** | `categorie` | `clinique` / `therapeutique` / `exercice` | Filtres : Ma pratique médicale / Dispositifs médicaux & médicaments / Mes tâches administratives |

### `categorie` (= sous-catégorie) — 3 valeurs EXACTES, rien d'autre (bug récurrent numéro 3)

Le portail filtre les sous-catégories avec `card.dataset.categorie === activeFilter`. Toute valeur hors liste = article invisible dans les sous-catégories.

| Valeur | Sous-catégorie portail | Quand l'utiliser |
|---|---|---|
| `clinique` | Ma pratique médicale | Études cliniques, guidelines pratique, procédures, diagnostic |
| `therapeutique` | Dispositifs médicaux & médicaments | Médicaments, dispositifs, pharmacovigilance, AMM |
| `exercice` | Mes tâches administratives | Réglementation admin, exercice professionnel, JORF non-médicament |

**INTERDIT** : `'innovation'`, `'recommandation'`, `'reglementaire'`, `'medicament'`, tout nom de sous-spécialité libre (`'valvulopathies'`, `'Hépatologie'`…), NULL.

Règle de choix rapide :
- Article sur un drug/device/AMM/pharmacovigilance → `therapeutique`
- Article admin/légal/exercice professionnel → `exercice`
- Tout le reste (études, guidelines, diagnostic, technique) → `clinique`

---

## 🔴 RÈGLE 2 — Toujours inclure sources réglementaires ET recommandations dans tout triage

**Jamais de triage 100% PubMed.** Après chaque lot de candidates spécialisées, scanner OBLIGATOIREMENT :

| Source | Contenu | Yield |
|---|---|---|
| `ansm_securite` | Alertes pharmacovigilance | ~42% |
| `ansm_ruptures_med` | Ruptures stock | ~90% |
| `ansm_ruptures_vaccins` | Ruptures vaccins | ~100% |
| `has_acces_precoces` | Accès précoces (ex-ATU) | ~68% |
| `has_rbp` | Recommandations bonne pratique | ~60% |
| `has_ct` | Avis Commission Transparence | ~67% |
| `legifrance_jorf` | Textes JORF (AMM, arrêtés) | ~2,5% |
| `ema_new_medicines` | Nouvelles AMM EMA | ~20-30% |
| `nejm`, `lancet`, `jama` | Générales — essais majeurs | ~2-5% |
| `cnom`, `ameli_medecin`, `carmf`, `csmf`, `mgfrance` | Médecin libéral — exercice professionnel | variable |

**Si reglementaire = 0 dans le lot → le lot N'EST PAS complet.** Chercher et insérer avant de clôturer.

SQL de vérification après chaque lot :
```sql
SELECT source_type, COUNT(*) FROM items WHERE specialty_slug='<slug>' GROUP BY 1 ORDER BY 2 DESC;
```

---

## 🔴 RÈGLE 3 — Ton rédactionnel (style journal médical spécialisé)

**Phrase 1 du résumé = résultat chiffré. Jamais la méthodologie.**

❌ INTERDIT : `"Méta-analyse de 93 RCTs (screening 33 220 abstracts)..."`
✅ EXIGÉ : `"Les benzodiazépines péri-opératoires majorent paradoxalement l'anxiété post-opératoire (+2,18 pts STAI, IC95% 1,05–3,30, 22 essais n=2 165)."`

`impact_pratique` : registre praticien-à-praticien. Jamais bureaucratique ("Revoir les protocoles selon…").

Auto-contrôle avant insertion : *"Le résultat principal est-il dans la première phrase ?"* — Si non, réécrire.

---

## 🔴 RÈGLE 4 — Insertion via psycopg2 inline uniquement

```bash
cat << 'PYEOF' | python3
import psycopg2, json, uuid
DB = "postgresql://neondb_owner:npg_sE8HTY1MrQCZ@ep-quiet-cell-al32rblz-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
conn = psycopg2.connect(DB)
# ...
PYEOF
```

**Jamais** de fichier `tmp_*.py`. **Jamais** de `load_dotenv()` dans les scripts Bash (lève AssertionError).

Template INSERT complet :
```python
cur.execute("""
    INSERT INTO items (id, candidate_id, audience, specialty_slug, tri_json, lecture_json,
                       review_status, categorie, source_type, score_density, llm_created_at, created_at)
    VALUES (%s, %s, 'SPECIALITE', %s, %s, %s, 'PENDING', %s, %s, 7, NOW(), NOW())
    ON CONFLICT DO NOTHING
""", (str(uuid.uuid4()), cand_id, slug, tri, lect, categorie, source_type))
cur.execute("UPDATE candidates SET status='LLM_DONE' WHERE id=%s", (cand_id,))
```

---

## 🔴 RÈGLE 5 — Filtre praticien (~15-20% de passage)

MedNews = newsletter réglementaire mensuelle pour médecins praticiens.

**Rejeter systématiquement :**
- Vidéos / interviews / podcasts (pas d'article primaire)
- Abstracts de congrès sans publication dans un journal indexé
- Études préliminaires sans résultat publiable
- Articles épidémiologiques sans impact décision clinique dans 1-3 ans
- Doublons de ce qui est déjà publié / connu depuis > 5 ans

**Retenir :**
- Essais randomisés / méta-analyses practice-changing
- Recommandations officielles (sociétés savantes, HAS, FDA, EMA)
- Alertes de sécurité (ANSM, EMA, FDA)
- Nouveaux accès précoces / AMM avec impact prescripteur direct

---

## 🔴 RÈGLE 6 — Q1-Q5 obligatoires après chaque lot inséré — AFFICHER les stats dans la réponse

**Ces stats DOIVENT être affichées explicitement dans chaque réponse après insertion. Ne pas seulement exécuter le SQL en silence.**

### Q1 — Répartition catégorie / sous-catégorie (OBLIGATOIRE, affiché sous forme de tableau — **spécialité traitée uniquement**)

`source_type` = **catégorie** (reglementaire / recommandation / innovation)
`categorie`   = **sous-catégorie** (clinique / therapeutique / exercice)

```sql
SELECT source_type, COUNT(*), ROUND(COUNT(*)*100.0/SUM(COUNT(*)) OVER(), 0) as pct
FROM items WHERE specialty_slug='<slug>' AND review_status != 'REJECTED'
GROUP BY 1 ORDER BY 2 DESC;
```

**Format de sortie obligatoire dans la réponse :**
```
Q1 — catégories [slug] (N total items) :
  innovation      : X  (XX%)
  recommandation  : X  (XX%)
  reglementaire   : X  (XX%)
```

**Actions obligatoires si répartition anormale — ne pas juste signaler, AGIR :**
- `reglementaire = 0` → relancer collecte sur ANSM/JORF/EMA/HAS pour la spé + trier les candidats NEW issus de ces sources
- `recommandation = 0` → chercher et ajouter des sources de recommandations manquantes (HAS RBP, sociétés savantes, guidelines) dans `pubmed_collector.py` ou `sources_europe.py`, puis relancer collecte
- `innovation > 90%` → identifier les sources réglementaires/recommandation non couvertes, les ajouter, relancer collecte et triage
- Dans tous les cas : ne pas clôturer la spécialité tant que la répartition n'est pas équilibrée ou que l'absence de reglementaire/recommandation n'est pas justifiée par une raison concrète (ex : spécialité très technique sans guidelines publiées)

### Q2 — Sous-catégories sous-représentées
Domaines avec < 3 items → chercher activement des sources complémentaires.

### Q3 — Actionabilité
```sql
SELECT evidence_json->>'actionability_horizon', COUNT(*)
FROM items WHERE specialty_slug='<slug>' GROUP BY 1;
```
→ Si > 30% en "3-5y" ou "exploratory" : signaler.

### Q4 — Ton rédactionnel
Relire 3 items au hasard : résumé commence par résultat chiffré ? impact_pratique praticien direct ?

### Q5 — Mise à jour `project_source_distribution.md`
```sql
SELECT c.source, COUNT(*) as nb
FROM items i JOIN candidates c ON i.candidate_id = c.id
WHERE i.specialty_slug = '<slug>' GROUP BY c.source ORDER BY nb DESC;
```
Mettre à jour immédiatement après chaque lot.
