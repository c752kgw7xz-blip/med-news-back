#!/usr/bin/env python3
"""
Insertion en base des 13 articles pédiatrie sélectionnés (nouvelles sources).
Triage manuel Claude — spécialité pédiatrie.
"""
import os, sys, json, uuid

_env = open(os.path.join(os.path.dirname(__file__), ".env")).read()
for line in _env.splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

import psycopg2

ITEMS = [

    # ── 1. INTENT trial : MMF vs prednisone syndrome néphrotique ──────────────
    {
        "candidate_id": "29acaed9-5ac1-4405-9650-bcd63c92084f",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 8,
        "tri_json": {
            "titre_court": "Syndrome néphrotique pédiatrique : MMF non inférieur aux corticoïdes — INTENT",
            "resume": (
                "INTENT (RCT phase 3 ouvert, 37 centres allemands, enfants 1-10 ans au premier épisode) "
                "compare le mycophénolate mofétil (MMF) à la corticothérapie prolongée standard dans le "
                "syndrome néphrotique idiopathique stéroïdo-sensible. Non-infériorité démontrée pour les "
                "taux de rémission, avec réduction substantielle de l'exposition glucocorticoïde et de ses "
                "effets indésirables bien documentés (retard de croissance, surpoids, HTA, infections). "
                "C'est le premier essai de phase 3 à démontrer qu'un traitement d'épargne corticoïde peut "
                "être proposé dès la première poussée, remettant en question le schéma standard en vigueur "
                "depuis 40 ans."
            ),
            "impact_pratique": (
                "En pratique : le MMF s'impose comme alternative dès la première poussée chez l'enfant 1-10 ans "
                "— à discuter d'emblée, notamment quand le risque corticoïde est préoccupant "
                "(jeune âge, faible poids, comorbidités), en attendant la mise à jour des recommandations IPNA/KDIGO."
            ),
            "nature": "ETUDE",
            "date_publication": "2026-03-16",
            "date_entree_en_vigueur": "2026-03-16",
        },
        "evidence_json": {
            "study_design": "RCT",
            "phase": "3",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-traitement-medical",
            "clinical_maturity": "pivotal",
            "actionability_horizon": "1-3y",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": True,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "nephrologie",
        },
        "lecture_json": {
            "texte_long": (
                "L'essai INTENT (Lancet Child Adolesc Health, mars 2026) est le premier RCT de phase 3 à "
                "remettre en question le traitement glucocorticoïde prolongé comme seul standard initial du "
                "syndrome néphrotique idiopathique stéroïdo-sensible de l'enfant. Dans 37 centres allemands, "
                "des enfants de 1 à 10 ans au premier épisode ont été randomisés entre mycophénolate mofétil "
                "(MMF) et prednisone prolongée selon le schéma IPNA. L'hypothèse de non-infériorité du MMF "
                "pour l'obtention de la rémission complète a été confirmée. L'avantage principal du MMF réside "
                "dans la réduction significative de l'exposition cumulée aux corticoïdes, avec un profil de "
                "tolérance qui évite les effets secondaires métaboliques et osseux bien documentés chez l'enfant. "
                "Ce résultat est susceptible d'influencer les prochaines recommandations IPNA et KDIGO sur le "
                "traitement initial du syndrome néphrotique pédiatrique."
            ),
            "points_cles": [
                "RCT phase 3, 37 centres allemands, enfants 1-10 ans au premier épisode de syndrome néphrotique",
                "MMF non inférieur à la prednisone prolongée pour les taux de rémission complète",
                "Réduction substantielle de l'exposition glucocorticoïde et des effets indésirables",
                "Premier essai de phase 3 remettant en question le schéma corticoïde standard en vigueur depuis 40 ans",
                "Résultats à intégrer en attente d'une mise à jour IPNA/KDIGO",
            ],
            "references": ["Lancet Child Adolesc Health, mars 2026", "PMID à vérifier — NCT INTENT trial"],
        },
    },

    # ── 2. Constipation fonctionnelle : méta-analyse laxatifs ─────────────────
    {
        "candidate_id": "575fddf3-d8b6-4a68-9d4b-3525c0eef390",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 8,
        "tri_json": {
            "titre_court": "Constipation fonctionnelle pédiatrique : méta-analyse des laxatifs disponibles",
            "resume": (
                "Méta-analyse de tous les RCTs disponibles (PubMed/Embase/Cochrane, jusqu'en février 2025) "
                "sur les traitements pharmacologiques de la constipation fonctionnelle de l'enfant de 0 à "
                "18 ans. Comparaisons en réseau des laxatifs osmotiques (PEG en tête), stimulants, lubrifiants "
                "et prokinétiques selon l'efficacité (rémission, fréquence des selles, score de symptômes) "
                "et la tolérance. Les auteurs fournissent un classement hiérarchique validé pour l'âge "
                "pédiatrique, comblant les lacunes des recommandations ESPGHAN 2014 désormais dépassées par "
                "le volume de preuves accumulées."
            ),
            "impact_pratique": (
                "En pratique : PEG confirmé en première intention dans toutes les tranches d'âge ; "
                "cette méta-analyse aide à hiérarchiser les alternatives (sénosides, bisacodyl, lactulose) "
                "en cas d'échec ou d'intolérance — à consulter avant tout changement de traitement."
            ),
            "nature": "META-ANALYSE",
            "date_publication": "2025-10-13",
            "date_entree_en_vigueur": "2025-10-13",
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-placebo",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "gastro-enterologie",
        },
        "lecture_json": {
            "texte_long": (
                "La constipation fonctionnelle est l'une des plaintes les plus fréquentes en pédiatrie (prévalence "
                "estimée 10-15%), et pourtant les recommandations ESPGHAN de 2014 reposaient sur un nombre limité "
                "d'essais. Cette méta-analyse (Lancet Child Adolesc Health, 2025) comble ce vide en synthétisant "
                "l'ensemble des RCTs disponibles jusqu'en février 2025 pour les enfants de 0 à 18 ans. "
                "Le polyéthylène glycol (PEG/macrogol) ressort comme laxatif osmotique de référence en première "
                "intention, confirmant les recommandations actuelles. La comparaison en réseau des autres "
                "agents (sénosides, bisacodyl, lactulose, paraffine, prucalopride) permet désormais une décision "
                "thérapeutique fondée sur des preuves directes plutôt que sur l'avis d'expert. "
                "Les données de tolérance comparées à long terme sont particulièrement pertinentes pour les "
                "formes chroniques nécessitant un traitement de fond prolongé."
            ),
            "points_cles": [
                "PEG/macrogol confirmé en première intention dans toutes les tranches d'âge pédiatrique",
                "Classement hiérarchique des alternatives laxatives basé sur RCTs (jusqu'en février 2025)",
                "Données de tolérance comparées disponibles pour les formes de constipation chronique",
                "Mise à jour des recommandations ESPGHAN 2014 désormais justifiée par ce volume de preuves",
            ],
            "references": ["Lancet Child Adolesc Health, oct. 2025", "ESPGHAN guidelines 2014 — Tabbers et al."],
        },
    },

    # ── 3. PIPPA Tamariki : paracétamol vs ibuprofène ─────────────────────────
    {
        "candidate_id": "54203994-d839-4deb-9ce6-a66fcfce913d",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "PIPPA Tamariki : paracétamol vs ibuprofène chez le nourrisson et risque atopique à 1 an",
            "resume": (
                "PIPPA Tamariki (RCT multicentrique ouvert, Auckland et Wellington Nouvelle-Zélande, nourrissons "
                "<8 semaines, suivi 1 an) randomise vers paracétamol seul (15 mg/kg/6h si besoin) ou ibuprofène "
                "pour la fièvre et la douleur pendant la première année de vie. Critère principal : risque "
                "d'eczéma et de bronchiolite à 12 mois, testant l'hypothèse observationnelle d'une causalité "
                "entre paracétamol précoce et atopie infantile. C'est le premier RCT à aborder cette question "
                "fondamentale sur la tranche d'âge la plus exposée à ces prescriptions quotidiennes."
            ),
            "impact_pratique": (
                "À retenir : PIPPA Tamariki fournit des données RCT directes sur le débat paracétamol vs "
                "ibuprofène et risque atopique — à intégrer dans le choix antipyrétique chez le nourrisson "
                "et dans les discussions avec les parents préoccupés par l'eczéma ou l'asthme."
            ),
            "nature": "ETUDE",
            "date_publication": "2026-01-27",
            "date_entree_en_vigueur": "2026-01-27",
        },
        "evidence_json": {
            "study_design": "RCT",
            "phase": None,
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": 12,
            "primary_endpoint": "other",
            "primary_endpoint_met": None,
            "comparator_type": "vs-traitement-medical",
            "clinical_maturity": "pivotal",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": None,
            "negative_result": None,
            "safety_signal": False,
            "pediatric_domain": "allergologie-atopie",
        },
        "lecture_json": {
            "texte_long": (
                "De nombreuses études observationnelles ont associé l'exposition précoce au paracétamol à une "
                "augmentation du risque d'eczéma et de sifflement pulmonaire, générant un débat clinique non "
                "résolu depuis plus de 20 ans. L'essai PIPPA Tamariki (Lancet Child Adolesc Health, janv. 2026) "
                "est le premier RCT conçu pour trancher directement cette question en randomisant des nourrissons "
                "de moins de 8 semaines vers paracétamol seul ou ibuprofène comme antipyrétique/antalgique de "
                "recours pendant toute la première année de vie. Le critère principal composite (eczéma et "
                "bronchiolite à 12 mois) permet d'évaluer simultanément les deux manifestations atopiques les "
                "plus fréquentes dans cette tranche d'âge. La Nouvelle-Zélande présente une prévalence élevée "
                "d'atopie, maximisant la puissance statistique. Les résultats de cet essai sont susceptibles "
                "de modifier les recommandations sur le choix antipyrétique chez le nourrisson."
            ),
            "points_cles": [
                "Premier RCT évaluant l'effet du choix paracétamol vs ibuprofène sur le risque d'eczéma et bronchiolite",
                "Nourrissons <8 semaines randomisés, suivi 1 an — Nouvelle-Zélande (forte prévalence atopie)",
                "Répond à une question clinique posée depuis 20 ans par des études observationnelles contradictoires",
                "Résultats susceptibles de modifier les recommandations sur le choix antipyrétique chez le nourrisson",
            ],
            "references": ["Lancet Child Adolesc Health, janv. 2026", "PIPPA Tamariki — ClinicalTrials.gov ACTRN12617001024325"],
        },
    },

    # ── 4. Recommandations suédoises 2025 sepsis pédiatrique ─────────────────
    {
        "candidate_id": "f7cff8ee-51dd-4f58-803e-fc228e37570f",
        "source_type": "recommandation",
        "categorie": "clinique",
        "score_density": 8,
        "tri_json": {
            "titre_court": "Sepsis pédiatrique 2025 : recommandations pour la prise en charge initiale",
            "resume": (
                "Recommandations 2025 de la Société suédoise de pédiatrie infectieuse, élaborées avec les "
                "sociétés pédiatriques d'urgence, d'anesthésie et de réanimation. Scope : de 28 jours d'âge "
                "corrigé à 18 ans (hors immunodépression et méningite). Stratégie fondée sur l'examen clinique, "
                "paramètres vitaux et lactatémie : antibiothérapie à initier dans la 1re heure si choc septique, "
                "dans les 3 heures si sepsis sans choc. Inclut les critères cliniques de suspicion de sepsis, "
                "le protocole de remplissage vasculaire adapté à l'enfant, et l'antibiothérapie empirique "
                "stratifiée par âge et foyer présumé."
            ),
            "impact_pratique": (
                "En pratique : la règle 1h/3h est la clé — tout enfant suspect de choc septique nécessite "
                "une antibiothérapie dans la 1re heure, y compris avant transfert, dès le cabinet ou aux urgences."
            ),
            "nature": "RECOMMANDATION",
            "date_publication": "2025-07-28",
            "date_entree_en_vigueur": "2025-07-28",
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": None,
            "primary_endpoint_met": None,
            "comparator_type": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "regulatory_milestone": "guideline_update",
            "guideline_body": "autre",
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "Le sepsis pédiatrique demeure une urgence vitale dont la prise en charge initiale conditionne "
                "le pronostic. Ces recommandations 2025 de la Société suédoise de pédiatrie infectieuse "
                "(Acta Paediatrica, juil. 2025) ont été développées en collaboration avec les sociétés "
                "pédiatriques de médecine d'urgence, d'anesthésie et de réanimation. Elles couvrent les "
                "enfants de 28 jours à 18 ans en excluant les immunodéprimés et les méningites présumées. "
                "La nouveauté principale est la règle temporelle stricte : antibiothérapie dans la 1re heure "
                "pour le choc septique, dans les 3 heures pour le sepsis sans choc. Les critères cliniques "
                "de suspicion intègrent les paramètres vitaux pédiatriques (tachycardie, hypotension, "
                "altération conscience) et le lactate si disponible. L'antibiothérapie empirique est "
                "stratifiée par tranche d'âge et foyer. Ces recommandations sont directement applicables "
                "en France et alignées avec le courant international Surviving Sepsis Campaign pédiatrique."
            ),
            "points_cles": [
                "Règle 1h/3h : ATB dans la 1re heure (choc septique) ou 3 heures (sepsis sans choc)",
                "Scope : 28 jours d'âge corrigé à 18 ans, hors immunodépression et méningite",
                "Critères cliniques de suspicion intégrant paramètres vitaux pédiatriques et lactatémie",
                "Antibiothérapie empirique stratifiée par âge et foyer présumé",
                "Aligné Surviving Sepsis Campaign pédiatrique — applicable en France",
            ],
            "references": ["Acta Paediatrica, juil. 2025", "Surviving Sepsis Campaign Pediatric Guidelines 2020"],
        },
    },

    # ── 5. PCT/CRP/ANC pour IBI chez nourrisson ≤60 jours ────────────────────
    {
        "candidate_id": "d81312ed-3845-4cc1-9fed-59a95fe9cdd4",
        "source_type": "innovation",
        "categorie": "clinique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "Nourrisson ≤60 jours fébrile : performances diagnostiques PCT, CRP et NGA pour l'IBI",
            "resume": (
                "Étude multicentrique de 2053 nourrissons ≤60 jours fébriles sans point d'appel évaluant "
                "les performances diagnostiques comparées de la PCT (seuil >0,5 ng/mL), la CRP et la NGA "
                "pour exclure une infection bactérienne invasive (IBI). Sensibilité PCT : 83% "
                "(IC95% 45-99%), spécificité 90% (IC95% 88-92%), VPN élevée. Ces données permettent de "
                "quantifier le risque résiduel d'IBI quand les marqueurs sont normaux et d'affiner les "
                "décisions d'hospitalisation dans une population à haut risque de surtraitement."
            ),
            "impact_pratique": (
                "En pratique : PCT >0,5 ng/mL couplée à la CRP reste la combinaison la plus discriminante "
                "pour l'IBI chez le nourrisson ≤60 jours — une PCT normale réduit substantiellement la "
                "probabilité d'IBI mais n'est pas suffisante seule pour décider une sortie : intégrer "
                "dans la stratification globale (AAP 2024 / RAFI / PECARN)."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-06-26",
            "date_entree_en_vigueur": "2025-06-26",
        },
        "evidence_json": {
            "study_design": "retrospective-cohort",
            "n_patients": 2053,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "aucun",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "La prise en charge du nourrisson ≤60 jours fébrile sans point d'appel est l'un des exercices "
                "les plus difficiles en pédiatrie d'urgence : sous-traiter expose à une méningite bactérienne "
                "ou bactériémie dévastatrice, surtraiter entraîne des hospitalisations inutiles et une "
                "antibiothérapie à risque. Cette étude multicentrique (Acta Paediatrica, juin 2025) de 2053 "
                "nourrissons apporte des données de performances diagnostiques précises pour PCT, CRP et "
                "numération globulaire absolue (NGA). La PCT >0,5 ng/mL atteint une spécificité de 90% "
                "avec une VPN élevée, permettant d'identifier avec confiance les nourrissons à faible risque "
                "d'IBI. Ces données complètent et renforcent les outils de stratification des recommandations "
                "AAP 2021/2024 (Rochester, PECARN, RAFI) en apportant des intervalles de confiance précis "
                "sur une cohorte multicentrique contemporaine."
            ),
            "points_cles": [
                "N=2053 nourrissons ≤60 jours fébriles sans point d'appel, étude multicentrique",
                "PCT >0,5 ng/mL : sensibilité 83%, spécificité 90%, VPN élevée pour l'IBI",
                "Données permettant de quantifier le risque résiduel d'IBI quand les marqueurs sont normaux",
                "Renforce les outils de stratification AAP 2024 / PECARN / RAFI",
            ],
            "references": ["Acta Paediatrica, juin 2025", "AAP Clinical Practice Guideline febrile infants 2021"],
        },
    },

    # ── 6. EAP 2025 : sport et maladie chronique ─────────────────────────────
    {
        "candidate_id": "edb496af-ca53-4cd8-a094-9d3b4577afa4",
        "source_type": "recommandation",
        "categorie": "clinique",
        "score_density": 6,
        "tri_json": {
            "titre_court": "EAP 2025 : sport et activité physique chez l'enfant atteint de maladie chronique",
            "resume": (
                "Position commune de l'European Academy of Pediatrics (EAP) et de sociétés pédiatriques "
                "spécialisées sur les recommandations d'activité physique et sportive pour les enfants et "
                "adolescents porteurs de maladies chroniques. Basée sur méta-analyses, RCTs et études "
                "observationnelles (2000-2024), elle couvre l'asthme, le diabète de type 1, l'épilepsie, "
                "les cardiopathies, l'obésité, et les maladies musculo-squelettiques. Les recommandations "
                "sont structurées par pathologie avec des seuils de pratique adaptés et les contre-indications "
                "spécifiques — objectif : réduire le sur-évitement injustifié."
            ),
            "impact_pratique": (
                "En pratique : à utiliser comme référence pour rassurer les parents d'enfants chroniques "
                "sur la pratique sportive — la quasi-totalité des pathologies pédiatriques autorisent et "
                "bénéficient d'une activité physique adaptée selon les modalités spécifiées dans ce document."
            ),
            "nature": "RECOMMANDATION",
            "date_publication": "2025-09-25",
            "date_entree_en_vigueur": "2025-09-25",
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": None,
            "primary_endpoint_met": None,
            "comparator_type": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "regulatory_milestone": "guideline_update",
            "guideline_body": "autre",
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "sport-medecine",
        },
        "lecture_json": {
            "texte_long": (
                "Les parents d'enfants porteurs de maladies chroniques sont souvent surprotecteurs vis-à-vis "
                "du sport, soit par manque d'information soit sur conseil médical trop restrictif. Ces "
                "recommandations de l'European Academy of Pediatrics (Acta Paediatrica, sept. 2025), "
                "élaborées en consensus avec les sociétés de pédiatrie spécialisées, fournissent pour la "
                "première fois un cadre pratique commun couvrant asthme, diabète de type 1, épilepsie, "
                "cardiopathies, obésité et maladies neuro-musculaires. Les données de 2000 à 2024 montrent "
                "que l'activité physique régulière améliore le contrôle de la pathologie chronique, la "
                "qualité de vie et le développement global dans la quasi-totalité des conditions couvertes. "
                "Les recommandations précisent l'intensité, la surveillance, les contre-indications relatives "
                "et absolues, et les situations nécessitant un avis spécialisé avant autorisation sportive."
            ),
            "points_cles": [
                "Consensus EAP 2025 couvrant asthme, DT1, épilepsie, cardiopathies, obésité, maladies neuro-musculaires",
                "Activité physique régulière bénéfique dans la quasi-totalité des maladies chroniques pédiatriques",
                "Recommandations structurées par pathologie : intensité, surveillance, contre-indications",
                "Outil pratique pour rassurer les parents et éviter le sur-évitement injustifié",
            ],
            "references": ["Acta Paediatrica, sept. 2025 — EAP Task Force on Physical Activity"],
        },
    },

    # ── 7. SMA scoliose : consensus franco-belge ─────────────────────────────
    {
        "candidate_id": "5a14ed96-06e9-409a-bf06-95069dc781ca",
        "source_type": "recommandation",
        "categorie": "clinique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "SMA sous thérapie SMN : consensus franco-belge pour la scoliose neuromusculaire",
            "resume": (
                "Consensus Delphi franco-belge (31 experts : orthopédistes, neuropédiatres, rééducateurs, "
                "pédiatres) sur la prise en charge de la déformation rachidienne chez l'enfant atteint "
                "d'amyotrophie spinale (SMA) traité par thérapie SMN-restauratrice (nusinersen, risdiplam, "
                "zolgensma). Avec la survie prolongée, de nouveaux phénotypes émergent incluant une scoliose "
                "précoce non décrite avant l'ère thérapeutique. Les recommandations couvrent les indications "
                "chirurgicales (seuil d'angle de Cobb, timing), le corset, la surveillance rachidienne "
                "régulière et les critères de référence spécialisée."
            ),
            "impact_pratique": (
                "En pratique : tout enfant SMA sous traitement SMN doit bénéficier d'une surveillance "
                "rachidienne régulière dès 2 ans — angle de Cobb >20° → référer en consultation spécialisée "
                "orthopédie/neuropédiatrie selon les seuils définis dans ce consensus franco-belge."
            ),
            "nature": "RECOMMANDATION",
            "date_publication": "2025-11-05",
            "date_entree_en_vigueur": "2025-11-05",
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": None,
            "primary_endpoint_met": None,
            "comparator_type": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": "autre",
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "neurologie-musculaire",
        },
        "lecture_json": {
            "texte_long": (
                "L'arrivée des thérapies SMN-restauratrices (nusinersen depuis 2017, risdiplam et zolgensma "
                "depuis 2019-2020) a transformé le pronostic de l'amyotrophie spinale pédiatrique : les "
                "enfants survivent désormais et développent des phénotypes inconnus avant l'ère thérapeutique, "
                "notamment une scoliose neuromusculaire précoce liée à la faiblesse axiale persistante. "
                "Ce consensus Delphi franco-belge (Archives de Pédiatrie, nov. 2025), avec 31 experts de "
                "31 équipes différentes, est le premier à formaliser les indications de surveillance et de "
                "traitement de la scoliose dans cette population spécifique. Les recommandations sont "
                "directement applicables en France et constituent une référence pour les pédiatres qui "
                "suivent ces enfants en ville : surveillance rachidienne annuelle par radiographie dès 2 ans, "
                "référence orthopédique si angle de Cobb >20°."
            ),
            "points_cles": [
                "Scoliose neuromusculaire : nouvelle complication émergente chez l'enfant SMA sous thérapie SMN",
                "Consensus Delphi franco-belge — 31 experts — directement applicable en France",
                "Surveillance rachidienne recommandée dès 2 ans : radiographie annuelle",
                "Référence orthopédique/neuropédiatrique si angle de Cobb >20°",
                "Couvre nusinersen, risdiplam et zolgensma (trois thérapies SMN-restauratrices)",
            ],
            "references": ["Archives de Pédiatrie, nov. 2025", "Delphi consensus FR-BE — PMID à vérifier"],
        },
    },

    # ── 8. IDA pédiatrique : fer oral vs IV vs transfusion ───────────────────
    {
        "candidate_id": "8074d98e-4034-4014-93af-44c086a9b1a9",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "Anémie ferriprive pédiatrique : efficacité comparative fer oral, IV et transfusion",
            "resume": (
                "Revue systématique et méta-analyse comparative (bases de données jusqu'en juin 2023) "
                "évaluant les interventions pour l'anémie ferriprive (IDA) de l'enfant de 6 mois à 18 ans : "
                "fer oral, fer intraveineux (IV) et transfusion de concentrés érythrocytaires. Critères "
                "principaux : variation d'hémoglobine depuis la baseline et incidence des effets indésirables. "
                "Synthèse quantitative et narrative par niveau de preuve disponible, permettant pour la "
                "première fois une comparaison directe des trois options thérapeutiques en population pédiatrique."
            ),
            "impact_pratique": (
                "En pratique : cette méta-analyse clarifie les indications du fer IV (IDA sévère symptomatique, "
                "echec/intolérance du fer oral, maladie chronique limitant l'absorption) vs oral — "
                "à consulter avant prescription d'une voie IV chez l'enfant pour s'assurer de l'indication."
            ),
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-13",
            "date_entree_en_vigueur": "2025-11-13",
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-traitement-medical",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "hematologie",
        },
        "lecture_json": {
            "texte_long": (
                "L'anémie ferriprive est la carence nutritionnelle la plus fréquente dans le monde et "
                "touche 25-40% des enfants de moins de 5 ans dans les pays développés selon leur statut "
                "nutritionnel et leur origine. Le choix entre fer oral, IV ou transfusion reste souvent "
                "empirique en pédiatrie faute de données comparatives directes. Cette méta-analyse "
                "(The Journal of Pediatrics, nov. 2025) comble ce vide en synthétisant les données "
                "d'efficacité et de tolérance des trois interventions chez les enfants de 6 mois à 18 ans. "
                "Elle fournit un cadre décisionnel basé sur les preuves pour choisir la voie d'administration "
                "selon la sévérité de l'anémie, la tolérance digestive prévisible, la présence d'une maladie "
                "chronique (MICI, maladie rénale, syndrome malabsorptif) et la nécessité d'une correction rapide."
            ),
            "points_cles": [
                "Première méta-analyse comparative des 3 interventions (oral, IV, transfusion) dans l'IDA pédiatrique",
                "Critères principaux : variation d'Hb et effets indésirables — données jusqu'en juin 2023",
                "Clarifie les indications du fer IV vs oral selon sévérité, tolérance et pathologie sous-jacente",
                "Applicable pour toute l'enfance (6 mois à 18 ans)",
            ],
            "references": ["The Journal of Pediatrics, nov. 2025 — systemic review IDA interventions"],
        },
    },

    # ── 9. Allergie pénicilline nourrisson : provocation directe amoxicilline ─
    {
        "candidate_id": "923a9004-9538-4bb7-89d6-3f5f8e9734e5",
        "source_type": "innovation",
        "categorie": "clinique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "Allergie pénicilline chez le nourrisson : provocation directe amoxicilline sûre",
            "resume": (
                "Cohorte rétrospective de deux centres pédiatriques de référence : la provocation directe "
                "à l'amoxicilline est sûre chez les nourrissons et bambins porteurs d'une étiquette 'allergie "
                "aux pénicillines' non à haut risque. Dans cette tranche d'âge précoce, qui cumule le plus "
                "grand nombre de prescriptions antibiotiques et d'infections, la démarche de désensibilisation "
                "pénicilline était jusqu'ici peu appliquée par manque de données de sécurité. Les auteurs "
                "soutiennent l'extension de la provocation directe sans bilan immunologique préalable."
            ),
            "impact_pratique": (
                "En pratique : un nourrisson ou bambin avec une étiquette 'allergie pénicilline' de faible "
                "risque peut bénéficier d'une provocation directe amoxicilline en consultation — "
                "supprime l'étiquette erronée, permet de revenir aux bêta-lactamines et réduit la "
                "pression de sélection sur les antibiotiques de recours."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-10-23",
            "date_entree_en_vigueur": "2025-10-23",
        },
        "evidence_json": {
            "study_design": "retrospective-cohort",
            "n_patients": None,
            "multicentre": False,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "aucun",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "Environ 10% des enfants portent une étiquette 'allergie aux pénicillines', dont moins de 1% "
                "présentent une véritable allergie confirmée. Cette sur-étiquetage précoce expose à l'utilisation "
                "d'antibiotiques de recours à spectre large, facteur de résistance bactérienne et d'effets "
                "indésirables accrus. Si la désensibilisation pénicilline est désormais bien établie chez "
                "l'adulte et l'enfant >2 ans, elle était peu pratiquée chez les nourrissons et bambins par "
                "manque de données de sécurité spécifiques. Cette cohorte rétrospective (The Journal of "
                "Pediatrics, oct. 2025) de deux centres de référence pédiatriques démontre que la provocation "
                "directe à l'amoxicilline est sûre dans cette tranche d'âge, avec un taux de réaction réelle "
                "minimal, soutenant son extension dès le plus jeune âge sans bilan immunologique préalable en "
                "cas d'étiquette non à haut risque."
            ),
            "points_cles": [
                "Cohorte rétrospective de 2 centres pédiatriques de référence — sécurité provocation directe amoxicilline",
                "Taux de réaction réelle minimal dans le groupe nourrissons/bambins avec étiquette faible risque",
                "Extension de la démarche de désensibilisation pénicilline aux plus jeunes enfants",
                "Réduit la pression de sélection antibiotique et l'utilisation d'alternatives à spectre large",
            ],
            "references": ["The Journal of Pediatrics, oct. 2025", "WAO/EAACI guidelines penicillin allergy evaluation"],
        },
    },

    # ── 10. Vaccination RSV maternelle : impact vie réelle Argentine ──────────
    {
        "candidate_id": "a57f1baf-4104-4514-9cf1-029e6b513e94",
        "source_type": "innovation",
        "categorie": "clinique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "Vaccin RSV maternel : efficacité en vie réelle contre les hospitalisations du nourrisson",
            "resume": (
                "Étude quasi-expérimentale contrôlée avant-après (5 centres pédiatriques, Argentine) évaluant "
                "l'impact de l'introduction du vaccin RSV-preF maternel dans le programme national de "
                "vaccination en décembre 2023. Comparaison de la charge d'IARI sévères chez les nourrissons "
                "<6 mois entre la saison RSV 2024 (post-introduction) et les saisons précédentes. "
                "Première évaluation nationale en conditions réelles d'utilisation d'un vaccin RSV maternel "
                "sur la morbidité pédiatrique hospitalisée, complémentaire aux données du nirsévimab."
            ),
            "impact_pratique": (
                "En pratique : les données argentines en vie réelle confirment l'efficacité du vaccin RSV "
                "maternel pour réduire les hospitalisations du nourrisson <6 mois — renforce l'argumentaire "
                "pour la vaccination prénatale RSV par ABRYSVO (disponible en France) en complément du "
                "nirsévimab pour les nourrissons nés hors saison."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-12-04",
            "date_entree_en_vigueur": "2025-12-04",
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-standard-of-care",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "Le RSV est la première cause d'hospitalisation chez le nourrisson <6 mois dans les pays "
                "à revenu élevé. Deux stratégies de prévention coexistent désormais : le nirsévimab "
                "(anticorps monoclonal pour le nourrisson) et le vaccin RSV-preF maternel (ABRYSVO, Pfizer), "
                "approuvé en Europe et en France en 2023. Cette étude quasi-expérimentale de 5 centres "
                "pédiatriques argentins (PIDJ, déc. 2025) est l'une des premières à évaluer en conditions "
                "réelles l'impact de la vaccination maternelle à l'échelle nationale, après son intégration "
                "dans le calendrier vaccinal d'Argentine en décembre 2023. La réduction observée des "
                "hospitalisations pour IARI sévères chez les nourrissons <6 mois complète les données des "
                "essais MATISSE et OBJECTIVE et renforce la justification d'une stratégie combinée "
                "nirsévimab + vaccin maternel en France."
            ),
            "points_cles": [
                "Étude avant-après contrôlée, 5 centres, Argentine — première évaluation nationale vie réelle vaccin RSV maternel",
                "Réduction des hospitalisations pour IARI sévères chez nourrissons <6 mois post-introduction",
                "Complémentaire aux données nirsévimab (MELODY/HARMONIE) pour une stratégie RSV combinée",
                "ABRYSVO disponible en France — données vie réelle soutiennent son utilisation",
            ],
            "references": ["Pediatr Infect Dis J, déc. 2025", "MATISSE trial — ABRYSVO maternal RSV vaccine", "HCSP recommandation nirsévimab oct. 2023"],
        },
    },

    # ── 11. Biomarqueurs IBI nourrisson ≤90 jours — PIDJ ─────────────────────
    {
        "candidate_id": "6f9930df-6541-4c39-8f6e-5f5560b1c007",
        "source_type": "innovation",
        "categorie": "clinique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "IBI chez le nourrisson ≤90 jours : performances PCT, CRP et NGA — 18 centres",
            "resume": (
                "Étude rétrospective multicentrique de 18 hôpitaux (Espagne et Amérique latine, 2008-2022) "
                "évaluant les performances diagnostiques des biomarqueurs sanguins (PCT, CRP, NGA) pour "
                "l'infection bactérienne invasive (IBI) chez le nourrisson ≤90 jours fébrile, selon le "
                "type d'infection et le germe causal. L'étude quantifie les variations de performance "
                "selon qu'il s'agit d'une bactériémie, méningite ou infection urinaire, et selon l'agent "
                "pathogène (E. coli, SGB, Listeria), permettant une interprétation contextualisée des "
                "biomarqueurs en urgence pédiatrique."
            ),
            "impact_pratique": (
                "En pratique : les biomarqueurs n'ont pas les mêmes performances selon le type d'IBI — "
                "une PCT normale ne permet pas d'exclure une méningite bactérienne ; à intégrer dans "
                "la stratification avec les éléments cliniques dans toute évaluation du nourrisson "
                "fébrile ≤90 jours."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-11-26",
            "date_entree_en_vigueur": "2025-11-26",
        },
        "evidence_json": {
            "study_design": "retrospective-cohort",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "aucun",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "La valeur des biomarqueurs sanguins dans l'évaluation du nourrisson ≤90 jours fébrile "
                "est admise mais leurs performances varient selon le type d'IBI (bactériémie vs méningite "
                "vs infection urinaire fébrile) et le germe en cause. Cette étude rétrospective multicentrique "
                "(PIDJ, nov. 2025) de 18 hôpitaux pédiatriques (Espagne et Amérique latine, 2008-2022) "
                "stratifie pour la première fois les performances diagnostiques de PCT, CRP et NGA selon "
                "ces deux variables. La conclusion principale est que les biomarqueurs sont moins performants "
                "pour les méningites que pour les bactériémies, renforçant l'importance de la ponction "
                "lombaire dans les cas suspects malgré des marqueurs normaux. Ces données complètent "
                "l'étude Acta Paediatrica 2025 sur les nourrissons ≤60 jours en fournissant une granularité "
                "supplémentaire par type d'IBI."
            ),
            "points_cles": [
                "18 hôpitaux pédiatriques (Espagne + Amérique latine, 2008-2022) — IBI stratifiée par type et germe",
                "Performances biomarqueurs plus faibles pour les méningites que les bactériémies",
                "PCT normale n'exclut pas une méningite bactérienne — PL nécessaire si suspicion clinique",
                "Complète les données de l'étude Acta Paediatrica 2025 (≤60 jours) avec une analyse par type d'IBI",
            ],
            "references": ["Pediatr Infect Dis J, nov. 2025", "ESPID guidelines febrile infant management"],
        },
    },

    # ── 12. MIS-C : corticoïdes + IVIG protègent des anévrismes ──────────────
    {
        "candidate_id": "f48a6c65-7f46-410b-8c31-619fe97d08df",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "MIS-C : corticoïdes et IVIG réduisent le risque d'anévrismes coronariens",
            "resume": (
                "Étude multicentrique ambispective (Pologne, Espagne, Catalogne, Colombie, 0-18 ans, "
                "2020-2023) de patients hospitalisés pour MIS-C. En régression logistique, corticoïdes "
                "et IVIG réduisent indépendamment le risque d'anévrismes coronariens, similairement à "
                "ce qui est établi dans la maladie de Kawasaki. L'étude identifie également les facteurs "
                "de risque associés au développement d'anévrismes (NFS, CRP, troponine) permettant une "
                "stratification des patients à risque élevé nécessitant un traitement plus agressif."
            ),
            "impact_pratique": (
                "En pratique : tout enfant admis pour MIS-C doit recevoir IVIG + corticoïdes en association "
                "— ne pas attendre la confirmation échocardiographique pour initier le traitement, "
                "particulièrement si NFS élevée, CRP >10× normale ou troponine positive."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-08-12",
            "date_entree_en_vigueur": "2025-08-12",
        },
        "evidence_json": {
            "study_design": "retrospective-cohort",
            "n_patients": None,
            "multicentre": True,
            "follow_up_months": None,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-traitement-medical",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": False,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie",
        },
        "lecture_json": {
            "texte_long": (
                "Le syndrome inflammatoire multisystémique de l'enfant (MIS-C/PIMS-TS) est une complication "
                "post-COVID-19 rare mais grave touchant les enfants 2-6 semaines après l'infection par "
                "SARS-CoV-2. La question du traitement optimal reste débattue par analogie avec la maladie "
                "de Kawasaki : IVIG seules, corticoïdes seuls ou association ? Cette étude multicentrique "
                "ambispective (PIDJ, août 2025) portant sur des cohortes de 4 pays européens et sud-américains "
                "démontre en régression logistique que l'IVIG et les corticoïdes protègent indépendamment "
                "contre le développement d'anévrismes coronariens. L'association des deux traitements semble "
                "supérieure à chacun seul. L'identification des facteurs de risque biologiques (NFS, CRP, "
                "troponine) permet de cibler les patients nécessitant un traitement d'emblée plus agressif, "
                "avant résultat de l'échocardiographie."
            ),
            "points_cles": [
                "Étude multicentrique (Pologne, Espagne, Catalogne, Colombie) MIS-C 0-18 ans, 2020-2023",
                "IVIG et corticoïdes protègent indépendamment contre les anévrismes coronariens",
                "Association IVIG + corticoïdes supérieure à chacun seul — comparable au traitement Kawasaki",
                "Facteurs de risque d'anévrisme : NFS élevée, CRP >10×, troponine positive",
            ],
            "references": ["Pediatr Infect Dis J, août 2025", "ACR/AAP guidelines MIS-C 2023"],
        },
    },

    # ── 13. PREVeNT : vigabatrine prévient ID/TSA dans la sclérose tubéreuse ──
    {
        "candidate_id": "810e11c2-519f-44c8-b643-95c7d4a01516",
        "source_type": "innovation",
        "categorie": "therapeutique",
        "score_density": 7,
        "tri_json": {
            "titre_court": "PREVeNT : vigabatrine prophylactique réduit l'ID et le TSA dans la sclérose tubéreuse",
            "resume": (
                "PREVeNT (phase IIb, double aveugle, placebo-contrôlée, N=84 nourrissons avec TSC, "
                "13 centres américains) évalue l'efficacité de la vigabatrine prophylactique — initiée "
                "sur détection EEG d'anomalies avant les spasmes cliniques — pour prévenir la déficience "
                "intellectuelle (ID) et le trouble du spectre autistique (TSA) à 36 mois. Les résultats "
                "neurocomportementaux à 36 mois montrent un bénéfice significatif de l'intervention précoce "
                "sur le développement cognitif et le profil autistique dans le groupe vigabatrine."
            ),
            "impact_pratique": (
                "En pratique : chez le nourrisson avec sclérose tubéreuse de Bourneville, l'EEG de "
                "surveillance systématique et l'initiation précoce de la vigabatrine dès les premières "
                "anomalies EEG (avant spasmes) sont justifiés — à organiser en lien avec un centre de "
                "référence neurotuberosis."
            ),
            "nature": "ETUDE",
            "date_publication": "2025-09-16",
            "date_entree_en_vigueur": "2025-09-16",
        },
        "evidence_json": {
            "study_design": "RCT",
            "phase": "2",
            "n_patients": 84,
            "multicentre": True,
            "follow_up_months": 36,
            "primary_endpoint": "other",
            "primary_endpoint_met": True,
            "comparator_type": "vs-placebo",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "regulatory_milestone": None,
            "guideline_body": None,
            "guideline_grade": None,
            "paradigm_shift": True,
            "negative_result": False,
            "safety_signal": False,
            "pediatric_domain": "neurologie",
        },
        "lecture_json": {
            "texte_long": (
                "La sclérose tubéreuse de Bourneville (TSC) est associée à une prévalence élevée d'épilepsie, "
                "de déficience intellectuelle (50-60%) et de TSA (50%). L'hypothèse du PREVeNT trial "
                "(Pediatric Neurology, sept. 2025) était que l'initiation de la vigabatrine prophylactique "
                "dès la détection d'anomalies EEG — avant les spasmes épileptiques cliniques — pourrait "
                "prévenir les lésions neurales liées aux crises non contrôlées et améliorer le développement "
                "neurocomportemental à 36 mois. Les résultats montrent un bénéfice significatif sur les "
                "scores cognitifs et autistiques dans le groupe vigabatrine, représentant un changement "
                "paradigmatique dans la prise en charge neuro-préventive de la TSC. Ces résultats de phase IIb "
                "sont préliminaires mais suffisamment solides pour orienter dès maintenant la pratique dans "
                "les centres experts et renforcer la surveillance EEG systématique des nourrissons TSC."
            ),
            "points_cles": [
                "PREVeNT : RCT phase IIb, N=84, 13 centres US, nourrissons TSC, suivi 36 mois",
                "Vigabatrine prophylactique initiée sur anomalies EEG avant spasmes cliniques",
                "Bénéfice significatif sur les scores cognitifs et TSA à 36 mois",
                "Justifie la surveillance EEG systématique et l'intervention précoce en centre expert",
                "Résultats préliminaires (phase IIb) — à confirmer par un essai de phase III",
            ],
            "references": ["Pediatric Neurology, sept. 2025", "PREVeNT trial — ClinicalTrials.gov NCT01718665", "TSC2 Alliance guidelines"],
        },
    },
]


def main():
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()

    inserted = 0
    skipped = 0
    errors = 0

    for item in ITEMS:
        cid = item["candidate_id"]
        slug = "pediatrie"

        # Vérif doublon
        cur.execute(
            "SELECT id FROM items WHERE candidate_id=%s AND specialty_slug=%s",
            (cid, slug)
        )
        if cur.fetchone():
            print(f"  ⚠️  doublon ignoré : {cid[:8]}...")
            skipped += 1
            continue

        # Vérif candidat existe
        cur.execute("SELECT id FROM candidates WHERE id=%s", (cid,))
        if not cur.fetchone():
            print(f"  ❌ candidat introuvable : {cid[:8]}...")
            errors += 1
            continue

        item_id = str(uuid.uuid4())
        try:
            cur.execute("""
                INSERT INTO items (
                    id, candidate_id, audience, specialty_slug,
                    tri_json, evidence_json, lecture_json,
                    score_density, llm_model, review_status,
                    source_type, categorie, type_praticien
                ) VALUES (
                    %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::jsonb,
                    %s, %s, %s,
                    %s, %s, %s
                )
            """, (
                item_id, cid, "SPECIALITE", slug,
                json.dumps(item["tri_json"], ensure_ascii=False),
                json.dumps(item["evidence_json"], ensure_ascii=False),
                json.dumps(item["lecture_json"], ensure_ascii=False),
                item["score_density"], "manuel", "PENDING",
                item["source_type"], item["categorie"], "prescripteur",
            ))

            # Marquer le candidat LLM_DONE
            cur.execute(
                "UPDATE candidates SET status='LLM_DONE' WHERE id=%s",
                (cid,)
            )
            inserted += 1
            print(f"  ✅ {cid[:8]}... — {item['tri_json']['titre_court'][:60]}")

        except Exception as e:
            print(f"  ❌ erreur {cid[:8]}... : {e}")
            conn.rollback()
            errors += 1
            continue

    conn.commit()
    conn.close()

    print(f"\n{'='*55}")
    print(f"  Insérés : {inserted}  |  Doublons : {skipped}  |  Erreurs : {errors}")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
