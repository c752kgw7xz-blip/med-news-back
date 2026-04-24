#!/usr/bin/env python3
"""Insertion des 50 items pédiatrie — triage manuel Claude, avril 2026."""
import os, json, uuid
from dotenv import load_dotenv
load_dotenv()
import psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur = conn.cursor()

SLUG = "pediatrie"

ITEMS = [
    # ── JAMA PEDIATRICS (10) ──────────────────────────────────────────────────
    {
        "candidate_id": "775462cd-5d28-41f6-baaf-a82e2466a323",
        "score": 8, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Nirsévimab : efficacité réelle saison RSV 2024-25",
            "resume": "Surveillance en vie réelle (7 centres pédiatriques US, octobre 2024 – avril 2025) évaluant l'efficacité du nirsévimab et du vaccin RSV maternel contre les IRA médicalement assistées à RSV chez les <2 ans, par design test-négatif. Résultats confirmant l'efficacité élevée des deux produits sur les hospitalisations.",
            "impact_pratique": "En pratique : les données 2024-25 confirment l'efficacité en vie réelle du nirsévimab — maintenir la recommandation systématique chez tous les nourrissons éligibles entrant dans leur première saison RSV.",
            "nature": "ETUDE",
            "date_publication": "2026-03-01"
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": ">2000",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "a11bc511-8c2e-4e43-ae11-e4faa7efd937",
        "score": 7, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Nirsévimab : méta-analyse hospitalisations LRTI nourrissons",
            "resume": "Méta-analyse d'études observationnelles post-AMM (2023–juin 2025, MEDLINE/Embase/medRxiv) sur l'efficacité réelle du nirsévimab contre les hospitalisations et passages aux urgences pour LRTI à RSV chez le nourrisson. Confirme une protection substantielle en dehors des essais cliniques.",
            "impact_pratique": "En pratique : le nirsévimab réduit significativement le risque d'hospitalisation pour LRTI en vie réelle — la systématisation chez les nourrissons est pleinement justifiée par ces données post-AMM.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled real-world observational",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "8c0c7bee-9f60-47be-acf0-ce2482032d13",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "GLP-1 RA obésité et DT2 pédiatriques : méta-analyse RCTs",
            "resume": "Méta-analyse de RCTs (jusqu'en février 2025) évaluant l'efficacité et la sécurité des agonistes du GLP-1 (semaglutide, liraglutide) chez les <18 ans avec obésité, pré-diabète ou DT2. Résultats : réduction significative de l'IMC et de l'HbA1c avec profil de sécurité acceptable — premières données synthétisées pour cette classe en pédiatrie.",
            "impact_pratique": "En pratique : les GLP-1 RA représentent une option pharmacologique validée pour l'obésité sévère et le DT2 pédiatrique — intégrer dans la discussion thérapeutique multidisciplinaire dès 12 ans selon AMM.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-12-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": True,
            "safety_signal": False,
            "pediatric_domain": "endocrinologie-metabolisme"
        }
    },
    {
        "candidate_id": "71d6de37-1b7d-468a-8f69-eb0e5e8bb6a2",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Boucle fermée hybride DT1 enfant : méta-analyse RCTs 2017-2025",
            "resume": "Méta-analyse de RCTs (MEDLINE/Embase/CINAHL/Cochrane, 2017-2025) sur les systèmes de délivrance automatisée d'insuline (AID/boucle fermée) chez les 6-18 ans avec DT1 en ambulatoire. Résultats : amélioration significative du temps en cible (TIR) et de l'HbA1c vs traitement conventionnel, sans surrisque hypoglycémique.",
            "impact_pratique": "En pratique : les systèmes AID/boucle fermée surpassent le traitement conventionnel en TIR et HbA1c chez l'enfant DT1 — recommander préférentiellement lors du choix du dispositif.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "endocrinologie-metabolisme"
        }
    },
    {
        "candidate_id": "6a68a8f5-d3c8-434e-af9c-b5e59fe2f76d",
        "score": 6, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "BRUE nourrisson : risques, facteurs pronostiques et bilans",
            "resume": "Méta-analyse (PubMed/Embase/Cochrane, 2016-juillet 2025) sur les BRUE chez le nourrisson. Fréquence de diagnostic sous-jacent grave ~4%, mortalité à 3 mois <1%. Facteurs pronostiques identifiés permettant une stratification bas/haut risque. Rendement diagnostique des explorations extensives quantifié.",
            "impact_pratique": "En pratique : utiliser la stratification AAP 2016 (bas risque) pour limiter les bilans invasifs — cette méta-analyse confirme que le rendement des explorations extensives est faible en l'absence de facteurs de risque.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-03-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled cohorts 2016-2025",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neonatologie-nourrisson"
        }
    },
    {
        "candidate_id": "19378ee2-c21d-4e9d-89c1-f6e449ceb029",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Interventions santé scolaires/communautaires et TA enfant",
            "resume": "Revue systématique des interventions scolaires ou communautaires sur la tension artérielle chez les 3-18 ans. Les programmes combinant alimentation et activité physique montrent une réduction modeste de la TA systolique, davantage dans les populations à risque.",
            "impact_pratique": "En pratique : orienter les enfants avec TA limite vers des programmes scolaires/communautaires multidisciplinaires — ces interventions offrent une réduction modeste mais sans effet secondaire.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "cardiologie-preventif"
        }
    },
    {
        "candidate_id": "67552b59-877a-48be-af3f-338d8c8d7522",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Survie grands prématurés 22-23 SA : 11 réseaux internationaux",
            "resume": "Analyse comparative de 11 réseaux néonataux internationaux (INEN collaboration) sur les issues des nouveau-nés nés à 22-23 SA avec soins actifs. La survie varie de 20 à 70% selon les réseaux, avec des taux de morbidités majeures persistantes. Données de référence pour le conseil prénatal.",
            "impact_pratique": "En pratique : utiliser ces données internationales pour structurer le conseil prénatal à 22-23 SA — la survie est possible mais les disparités entre centres imposent de s'appuyer sur les données locales de son unité.",
            "nature": "ETUDE",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": ">5000",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neonatologie-nourrisson"
        }
    },
    {
        "candidate_id": "8ef904bd-b203-4d7a-87c7-4009da21323a",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Hydrocortisone préventive DBP : suivi neurodéveloppemental scolaire",
            "resume": "Suivi à long terme (âge scolaire) de l'essai NRN sur l'hydrocortisone préventive chez les prématurés à haut risque de dysplasie bronchopulmonaire. Évalue l'impact neurodéveloppemental de ce traitement — donnée clé manquante pour la décision thérapeutique en NICU.",
            "impact_pratique": "En pratique : les données de suivi scolaire doivent informer l'utilisation de l'hydrocortisone préventive en NICU — discuter le rapport bénéfice pulmonaire / risque neurodéveloppemental.",
            "nature": "ETUDE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": "NRN RCT long-term follow-up",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neonatologie-nourrisson"
        }
    },
    {
        "candidate_id": "832d1e8d-f81f-41e0-a69a-8336e1c09d6a",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Dépistage IST adolescents aux urgences : ciblé vs universel",
            "resume": "Étude comparative (soins habituels vs dépistage ciblé vs universel gonorrhée/chlamydia) aux urgences chez les adolescents. Les adolescents représentent ~50% des 2,5 millions d'IST diagnostiquées/an aux US. Le dépistage opportuniste aux urgences détecte des cas non identifiés.",
            "impact_pratique": "En pratique : proposer un dépistage opportuniste gonorrhée/chlamydia aux adolescents sexuellement actifs se présentant aux urgences — indépendamment du motif de consultation.",
            "nature": "ETUDE",
            "date_publication": "2025-12-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "multicenter ED adolescents",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "adolescents"
        }
    },
    {
        "candidate_id": "311afc49-7a78-4d22-b003-2af0cd722efe",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Opioïdes SCD aux urgences : délai d'administration et hospitalisations",
            "resume": "Étude multisite PECARN évaluant l'association entre la rapidité d'administration d'opioïdes multiples et les hospitalisations lors des crises drépanocytaires pédiatriques aux urgences. Une prise en charge rapide est associée à une réduction des hospitalisations.",
            "impact_pratique": "En pratique : lors d'une crise drépanocytaire, administrer le premier opioïde dans les 60 minutes — le délai de prise en charge conditionne directement le risque d'hospitalisation.",
            "nature": "ETUDE",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "PECARN multicenter",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-hematologie"
        }
    },
    # ── PEDIATRICS GUIDELINES (11) ────────────────────────────────────────────
    {
        "candidate_id": "b27b7e8c-65d7-47b9-a3cd-34ec55e1d0da",
        "score": 8, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Réanimation néonatale AHA/AAP 2025 : nouvelles recommandations",
            "resume": "Mise à jour 2025 des recommandations AHA/AAP pour la réanimation néonatale en salle de naissance. Points clés : clampage différé du cordon ≥60 secondes recommandé par défaut, soins peau-à-peau prioritaires, thermorégulation proactive dès la naissance. Intègre les données ILCOR les plus récentes.",
            "impact_pratique": "En pratique : appliquer les recommandations 2025 — clampage différé ≥60s systématique sauf urgence, et revoir les protocoles de salle de naissance.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-01-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neonatologie-nourrisson"
        }
    },
    {
        "candidate_id": "3f9973a0-04e1-45de-b170-78567089ccbe",
        "score": 8, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "BLS pédiatrique AHA/AAP 2025 : première refonte depuis 2020",
            "resume": "Première mise à jour complète depuis 2020 des recommandations AHA/AAP pour la réanimation de base (BLS) de l'enfant. Intègre les données ILCOR sur les séquences de RCP, l'utilisation des DEA en pédiatrie, et les chaînes de survie. Document de référence pour la formation.",
            "impact_pratique": "En pratique : mettre à jour les formations BLS pédiatriques selon les recommandations 2025 — revoir les algorithmes DEA et séquences de RCP pour toutes les équipes.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-01-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-reanimation"
        }
    },
    {
        "candidate_id": "35f85141-b5fb-4f83-895d-3d7f1bf89a04",
        "score": 8, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "AAP 2025 : recommandations prévention RSV nourrissons",
            "resume": "Mise à jour AAP 2025 pour la prévention du RSV chez les nourrissons. Le nirsévimab devient l'immunoprophylaxie préférée pour tous les nourrissons <8 mois entrant dans leur première saison RSV. Précise les critères du palivizumab pour les populations à risque et intègre les données de la saison 2024-25.",
            "impact_pratique": "En pratique : proposer systématiquement le nirsévimab à tous les nourrissons <8 mois avant/pendant la saison RSV — le palivizumab reste pour les groupes à risque élevé spécifiés.",
            "nature": "RECOMMANDATION",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "ad18053a-3d0a-4471-a879-e01896fddaed",
        "score": 7, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "PALS AHA/AAP 2025 : réanimation avancée pédiatrique",
            "resume": "Recommandations 2025 pour le support avancé des fonctions vitales pédiatriques (PALS). Mise à jour des algorithmes de prise en charge de l'ACR, du choc, de l'état de mal épileptique et des voies aériennes chez l'enfant de la naissance à 18 ans.",
            "impact_pratique": "En pratique : mettre à jour les protocoles PALS institutionnels selon les recommandations 2025 — former les équipes aux nouveaux algorithmes de prise en charge du choc et de l'ACR pédiatrique.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-01-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-reanimation"
        }
    },
    {
        "candidate_id": "fa9e39df-9d8f-423d-ba40-94e03c48407c",
        "score": 7, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "AAP grippe 2025-2026 : vaccins et antiviraux chez l'enfant",
            "resume": "Recommandations AAP pour la prévention et le traitement de la grippe chez l'enfant en 2025-2026. Vaccination annuelle universelle dès 6 mois, mise à jour des formulations et des stratégies antivirales (oseltamivir, baloxavir), orientations pour immunodéprimés.",
            "impact_pratique": "En pratique : vacciner annuellement tous les enfants ≥6 mois et prescrire l'oseltamivir précocement chez les enfants à risque dès suspicion clinique de grippe.",
            "nature": "RECOMMANDATION",
            "date_publication": "2025-12-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "20f73e85-cad3-4de3-8376-dbb284400d81",
        "score": 6, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Allergie alimentaire à l'école : rapport clinique AAP 2025",
            "resume": "Mise à jour AAP 2025 du rapport clinique sur la gestion des allergies alimentaires en milieu scolaire. L'allergie alimentaire touche jusqu'à 10% des enfants ; l'anaphylaxie survient dans 1 école sur 15 par an. Définit le rôle du pédiatre dans la coordination des plans d'urgence.",
            "impact_pratique": "En pratique : établir un plan d'urgence individualisé pour chaque enfant allergique scolarisé, avec prescription d'adrénaline auto-injectable transmise à l'établissement.",
            "nature": "RECOMMANDATION",
            "date_publication": "2025-12-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "allergologie"
        }
    },
    {
        "candidate_id": "f62a686b-d33b-4e65-9208-0ca7a4eafc4a",
        "score": 6, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "AAP 2025 : vaccins COVID nourrissons, enfants, adolescents",
            "resume": "Mise à jour AAP des recommandations pour la vaccination COVID-19 chez les nourrissons, enfants et adolescents (2025). Intègre les nouvelles formulations adaptées aux variants circulants, les données d'efficacité et les recommandations pour les enfants immunodéprimés ou à risque de forme grave.",
            "impact_pratique": "En pratique : appliquer le calendrier vaccinal COVID-19 AAP 2025 aux enfants éligibles, en priorité pour les populations à risque élevé de forme grave.",
            "nature": "RECOMMANDATION",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "ce474b73-606f-4e6a-8f38-5ad7b2842f44",
        "score": 5, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Calendrier vaccinal US 2026 enfants et adolescents",
            "resume": "Calendrier vaccinal recommandé 2026 pour les enfants et adolescents américains. Intègre les nouvelles recommandations pour le RSV (nirsévimab), la grippe 2025-26, les mises à jour du calendrier de rattrapage. Document de référence annuel pour le suivi vaccinal.",
            "impact_pratique": "En pratique : utiliser le calendrier vaccinal 2026 comme référence à chaque consultation de suivi pédiatrique pour vérifier le statut vaccinal et combler les retards.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-03-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "preventif"
        }
    },
    {
        "candidate_id": "aaa30750-7565-4152-910a-de224aad18c0",
        "score": 5, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Écosystème numérique enfants : rapport technique AAP 2025",
            "resume": "Rapport technique AAP 2025 sur l'impact des écosystèmes numériques (IA, réseaux sociaux, jeux vidéo, wearables, RA/VR) sur les enfants et adolescents. Dépasse le concept de 'temps d'écran' pour analyser la qualité et le contexte des usages numériques familiaux.",
            "impact_pratique": "En pratique : intégrer l'évaluation des usages numériques dans les bilans annuels — la qualité des usages prime sur le temps quantitatif ; un plan familial d'usage reste la recommandation clé.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "preventif-sante-mentale"
        }
    },
    {
        "candidate_id": "5d0e2d22-3e1c-462a-a7cc-b85314832c1c",
        "score": 5, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Cassure de courbe pondérale et précarité : rapport technique AAP",
            "resume": "Rapport technique AAP sur le lien entre statut socio-économique (SES) et cassure de courbe staturo-pondérale (faltering weight) chez les <5 ans, et l'efficacité comparative des traitements. Le SES bas est un facteur de risque confirmé ; les interventions multidisciplinaires (diét., social, med.) sont les plus efficaces.",
            "impact_pratique": "En pratique : intégrer systématiquement le contexte socio-économique dans l'évaluation d'une cassure de courbe — orienter vers une équipe multidisciplinaire incluant diététicien et travailleur social.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-03-16"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "nutrition-pediatrie-generale"
        }
    },
    {
        "candidate_id": "c30524e9-96e2-41ed-8ab1-157b6fe2ce24",
        "score": 5, "source_type": "recommandation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Chorée de Sydenham : 88 recommandations de consensus 2025",
            "resume": "Consensus international de 27 experts (neurologues, psychiatres, représentants de patients, tous continents) via processus Delphi. 88 recommandations sur le diagnostic (chorée, hypotonie), le dépistage comportemental/psychiatrique et le traitement de la chorée de Sydenham. Première recommandation internationale dédiée.",
            "impact_pratique": "En pratique : suspecter une chorée de Sydenham devant tout mouvement anormal chez l'enfant avec antécédent streptococcique — appliquer les recommandations 2025 pour le bilan (échocardiographie, ASLO) et le traitement.",
            "nature": "RECOMMANDATION",
            "date_publication": "2025-12-01"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neurologie"
        }
    },
    # ── PEDIATRICS (6) ────────────────────────────────────────────────────────
    {
        "candidate_id": "9e04b25e-d387-4b8e-83b1-d6048792fbd6",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Modulateurs CFTR et diabète mucoviscidosien : méta-analyse",
            "resume": "Méta-analyse (littérature depuis 2011) évaluant l'impact des modulateurs CFTR (élexacaftor-tézacaftor-ivacaftor) sur l'équilibre glycémique dans la mucoviscidose. Les modulateurs améliorent significativement le contrôle glycémique et réduisent le risque de CFRD — changement de prise en charge attendu.",
            "impact_pratique": "En pratique : sous modulateurs CFTR, réévaluer la stratégie de surveillance et de traitement du CFRD — une amélioration glycémique est attendue, pouvant justifier la diminution ou l'arrêt de l'insulinothérapie.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs+observational CF registries",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-endocrinologie"
        }
    },
    {
        "candidate_id": "c7f6d83a-2e2d-44bf-9423-acd7a217d4c6",
        "score": 6, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Efficacité vaccinale grippe : enfants avec vs sans comorbidités",
            "resume": "Évaluation de l'efficacité vaccinale (VE) de la grippe chez les enfants avec pathologie sous-jacente vs enfants sains (urgences US, surveillance active). Les enfants à risque bénéficient autant de la vaccination que les enfants sains, justifiant l'insistance sur la couverture vaccinale dans ces groupes.",
            "impact_pratique": "En pratique : la vaccination antigrippale est aussi efficace chez les enfants avec comorbidités — renforcer la recommandation vaccinale annuelle dans ces groupes à risque.",
            "nature": "ETUDE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "multicenter ED surveillance US",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie"
        }
    },
    {
        "candidate_id": "31746c98-1b07-4e7d-b509-7fe42f33e93d",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_cout": "Test MeMed BV protéines hôte : impact décision urgences pédiatriques",
            "titre_court": "Test MeMed BV protéines hôte : impact décision urgences pédiatriques",
            "resume": "Étude pragmatique sur l'impact du test MeMed BV (TRAIL, IP-10, CRP) sur la décision clinique dans les infections pédiatriques aux urgences. Le test oriente la décision de référer aux urgences et de prescrire des antibiotiques dans les situations d'incertitude diagnostique.",
            "impact_pratique": "En pratique : le test MeMed BV est un outil de différenciation viral/bactérien à fort potentiel aux urgences pédiatriques — à intégrer quand disponible dans les situations diagnostiquement incertaines.",
            "nature": "ETUDE",
            "date_publication": "2026-01-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "urgent care centers pragmatic study",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-infectiologie"
        }
    },
    {
        "candidate_id": "5655b323-4385-4721-b2d3-2d6d2aec25a3",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Adhérence pédiatre prévention allergie arachide : essai iREACH",
            "resume": "Essai randomisé iREACH (cluster, cabinets pédiatriques US) testant une intervention pour améliorer l'adhérence des pédiatres aux recommandations US 2017 d'introduction précoce de l'arachide. L'adhérence reste insuffisante malgré l'ancienneté des recommandations, compromettant la prévention de l'allergie.",
            "impact_pratique": "En pratique : recommander systématiquement l'introduction de l'arachide dès 4-6 mois aux nourrissons à risque (eczéma, allergie œuf) — c'est encore insuffisamment appliqué en consultation.",
            "nature": "ETUDE",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": "cluster RCT pediatric practices",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "allergologie"
        }
    },
    {
        "candidate_id": "f3fe4d72-81eb-4834-bb95-7e0c095437e5",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Commotion cérébrale jeune enfant : symptômes persistants à 1 an",
            "resume": "Cohorte multicentrique (urgences Canada/US) d'enfants 6 mois-6 ans avec commotion cérébrale. Évalue la fréquence des symptômes persistants à 1 an (PSaC) et identifie les facteurs prédicteurs — données manquantes pour cette tranche d'âge jusqu'alors.",
            "impact_pratique": "En pratique : informer les parents que des symptômes peuvent persister >1 mois chez le jeune enfant après commotion — programmer un suivi à 1 mois et surveiller les facteurs prédicteurs.",
            "nature": "ETUDE",
            "date_publication": "2026-02-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "multicenter ED Canada/US",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "neurologie-urgences"
        }
    },
    {
        "candidate_id": "97a6572e-25c7-4985-9144-2f45f83476ce",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Bronchiolite en soins primaires : réduction bronchodilatateurs",
            "resume": "Initiative qualité dans un grand réseau de soins primaires visant à réduire l'utilisation des bronchodilatateurs dans la bronchiolite (objectif 24%→15%). Résultat : objectif atteint sans augmentation des corticoïdes, confirmant la faisabilité d'une déprescription à grande échelle.",
            "impact_pratique": "En pratique : ne pas prescrire de bronchodilatateurs dans la bronchiolite légère à modérée en soins primaires — la déprescription est sûre et réalisable même dans des structures larges.",
            "nature": "ETUDE",
            "date_publication": "2025-11-01"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "large primary care network QI",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-soins-primaires"
        }
    },
    # ── ARCHIVES OF DISEASE IN CHILDHOOD (11) ────────────────────────────────
    {
        "candidate_id": "a9a78a2c-86a2-4b25-bef3-a9d47cb2f2f8",
        "score": 7, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Règle PECARN nourrissons fébriles <60j : validation européenne",
            "resume": "Validation externe de la règle PECARN dans des cohortes européennes (MOFICHE, 12 urgences pédiatriques EU ; Suède, 4 urgences, N=536). La règle montre une sensibilité acceptable pour le dépistage des infections bactériennes sévères, et la CRP peut remplacer la procalcitonine.",
            "impact_pratique": "En pratique : appliquer la règle PECARN (avec CRP si procalcitonine indisponible) pour stratifier le risque des nourrissons fébriles <60 jours — elle est validée dans le contexte européen.",
            "nature": "ETUDE",
            "date_publication": "2026-03-19"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": "N=536 Sweden + MOFICHE 12 EU EDs",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-neonatologie"
        }
    },
    {
        "candidate_id": "31b30b09-4419-4e63-947b-7d6ef127a2c4",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Magnésium IV asthme aigu enfant : méta-analyse 9 RCTs (N=473)",
            "resume": "Méta-analyse de 9 RCTs (N=473) sur le sulfate de magnésium IV en add-on au traitement standard (SABA + corticoïdes) de l'asthme aigu pédiatrique. Réduction significative du taux d'hospitalisation (RR=0,70, IC95% 0,54-0,90) et du besoin de VNI (RR=0,17, p=0,003).",
            "impact_pratique": "En pratique : administrer le sulfate de magnésium IV dans les asthmes aigus sévères ne répondant pas aux SABA — la réduction d'hospitalisation (RR=0,70) justifie son usage systématique en 2ème ligne aux urgences.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": 473,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-urgences"
        }
    },
    {
        "candidate_id": "4beccdca-019d-4171-863c-2e8c7058caef",
        "score": 6, "source_type": "recommandation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "HFNC bronchiolite <2 ans : synthèse des recommandations nationales",
            "resume": "Revue systématique des guidelines nationales/internationales sur l'oxygénothérapie haut débit (HFNC) dans les infections respiratoires basses du nourrisson 1-23 mois. Synthèse des recommandations sur l'initiation, la surveillance, le sevrage et les modalités d'alimentation sous HFNC.",
            "impact_pratique": "En pratique : utiliser cette synthèse pour standardiser les protocoles HFNC en bronchiolite — les critères d'initiation et de sevrage varient fortement entre centres faute d'harmonisation.",
            "nature": "RECOMMANDATION",
            "date_publication": "2026-03-19"
        },
        "evidence_json": {
            "study_design": "guideline",
            "n_patients": None,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie"
        }
    },
    {
        "candidate_id": "d8c85d17-1d19-45ab-9151-d9fb182c83e8",
        "score": 6, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Ipratropium bromide asthme aigu enfant : méta-analyse RCTs",
            "resume": "Méta-analyse de RCTs (MEDLINE/Embase/CINAHL jusqu'en juillet 2024) sur l'ipratropium inhalé en add-on aux SABA dans l'asthme aigu pédiatrique. Évalue l'efficacité sur la morbidité, l'escalade thérapeutique, la durée d'hospitalisation et les effets secondaires.",
            "impact_pratique": "En pratique : l'ipratropium inhalé en association aux SABA reste un traitement validé en 1ère ligne dans les crises d'asthme modérées à sévères de l'enfant — cette méta-analyse consolide les données.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled 24 RCTs",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-urgences"
        }
    },
    {
        "candidate_id": "3ac54797-79dc-4b58-9532-9d960fa88aff",
        "score": 6, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Aminophylline IV asthme aigu sévère enfant : méta-analyse 1966-2024",
            "resume": "Méta-analyse (1966-mai 2024, MEDLINE/Embase/Cochrane) évaluant l'aminophylline IV en add-on dans l'asthme aigu sévère pédiatrique. Bénéfice sur la fonction respiratoire et l'hospitalisation confirmé, au prix d'effets secondaires (nausées, arythmies) nécessitant une surveillance.",
            "impact_pratique": "En pratique : réserver l'aminophylline IV aux asthmes aigus sévères résistants au traitement de 1ère ligne — son bénéfice est établi mais la fenêtre thérapeutique étroite impose un monitoring.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs 1966-2024",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": True,
            "pediatric_domain": "pneumologie-urgences"
        }
    },
    {
        "candidate_id": "865abae2-9edd-4f6c-8563-13cfa96c6d46",
        "score": 6, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Traitement 2ème ligne asthme sévère enfant : méta-analyse comparative",
            "resume": "Méta-analyse de RCTs comparant les traitements de 2ème ligne (aminophylline IV, SABA IV, magnésium IV, kétamine, adrénaline SC) dans l'asthme aigu sévère pédiatrique. Fournit une comparaison directe des efficacités relatives et des profils de tolérance pour guider le choix thérapeutique.",
            "impact_pratique": "En pratique : utiliser cette méta-analyse comparative pour guider le choix du traitement de 2ème ligne dans l'asthme sévère — le sulfate de magnésium IV présente le meilleur profil efficacité/tolérance.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs multiple arms",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-urgences"
        }
    },
    {
        "candidate_id": "70cb6370-d200-4da7-ad75-8d133a814bdd",
        "score": 6, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Infection bactérienne invasive nourrisson fébrile + ECBU positif : FIDO",
            "resume": "Analyse secondaire de la cohorte FIDO (35 urgences UK/Irlande, N=1480 nourrissons ≤90j). Parmi les nourrissons avec bandelette urinaire positive, 7,7% avaient une IBI (méningite/bactériémie), vs 2,2% avec bandelette négative. La bandelette positive multiplie le risque d'IBI par 3,5.",
            "impact_pratique": "En pratique : devant un nourrisson ≤90j fébrile avec bandelette urinaire positive, rechercher activement une IBI (hémoculture, ± PL) — le risque est 3,5 fois plus élevé qu'avec une bandelette négative.",
            "nature": "ETUDE",
            "date_publication": "2025-12-15"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": 1480,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "urgences-infectiologie"
        }
    },
    {
        "candidate_id": "0c5a556b-d098-48aa-846e-7a5afb4d39a6",
        "score": 6, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Coqueluche grave PICU Grande-Bretagne 2023-24 : 54 cas, 20% mortalité",
            "resume": "Audit national de tous les PICU britanniques sur les coqueluches graves (nov. 2023 – juin 2024). N=54 enfants, âge médian 43 jours, mortalité 20% (11/54). Seulement 23% des mères vaccinées pendant la grossesse vs 59% de moyenne nationale. La leuco-réduction d'urgence est le facteur pronostique clé.",
            "impact_pratique": "En pratique : renforcer systématiquement la vaccination coqueluche au 3ème trimestre — la couverture insuffisante (23%) est directement responsable de cette mortalité néonatale évitable.",
            "nature": "ETUDE",
            "date_publication": "2025-11-19"
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": 54,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": True,
            "pediatric_domain": "infectiologie-reanimation"
        }
    },
    {
        "candidate_id": "cc7058e6-e02a-4391-b3a1-41e22cae2dac",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Tumeurs abdominales enfant : signes pré-diagnostiques en méta-analyse",
            "resume": "Revue systématique et méta-analyse (MEDLINE/Embase, 2005-2023) des signes cliniques pré-diagnostiques des tumeurs abdominales pédiatriques. Identification des symptômes les plus discriminants pour améliorer la détection précoce et réduire le délai diagnostique.",
            "impact_pratique": "En pratique : devant une masse abdominale palpable, une douleur abdominale persistante ou une hématurie chez l'enfant — engager immédiatement l'imagerie sans attente.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-01-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled studies 2005-2023",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "oncologie-pediatrie-generale"
        }
    },
    {
        "candidate_id": "547acd56-48d7-4122-b416-949d0cbe8fa5",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Hypertension artérielle enfant en Europe : méta-analyse 1990-présent",
            "resume": "Revue systématique et méta-analyse d'études populationnelles européennes (1990-présent) sur la prévalence de l'HTA chez les enfants et adolescents. La prévalence varie de 1 à 20% selon les seuils retenus, avec une tendance à la hausse liée à l'épidémie d'obésité.",
            "impact_pratique": "En pratique : mesurer la TA à chaque consultation de suivi dès 3 ans — la prévalence de l'HTA pédiatrique en Europe est probablement sous-estimée et détectée trop tardivement.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-19"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled European population studies",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "cardiologie-preventif"
        }
    },
    {
        "candidate_id": "deaa3bab-521e-470c-979e-0347c9cb1f4c",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Insuline glargine précoce dans l'ACR pédiatrique : RCT double aveugle",
            "resume": "RCT en double aveugle (urgences + PICU, Inde, juillet 2022-juin 2023) évaluant la supplémentation précoce en insuline glargine (overlap ≥4h avec insuline IV) dans l'acidocétose diabétique de l'enfant >1 mois-12 ans. Critère principal : temps de résolution de l'acidocétose.",
            "impact_pratique": "En pratique : l'insuline glargine précoce lors de l'ACR pédiatrique peut réduire la durée de résolution — à comparer avec les données de la méta-analyse EJP concomitante avant d'adapter les protocoles.",
            "nature": "ETUDE",
            "date_publication": "2025-11-19"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": "double-blind pediatric DKA RCT India",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "endocrinologie-urgences"
        }
    },
    # ── EUR J PEDIATR (12) ────────────────────────────────────────────────────
    {
        "candidate_id": "7d897058-c5e7-48b2-8538-3369614896e9",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Transition IV→PO antibiotiques ostéo-arthrite pédia : 24 études (N=7881)",
            "resume": "Méta-analyse de 24 études (N=7881) comparant la transition précoce IV→oral vs IV prolongé dans les infections ostéo-articulaires pédiatriques. Aucune différence significative de complications (RR=0,82, IC95% 0,62-1,08, p=0,2) — la transition orale précoce est non inférieure.",
            "impact_pratique": "En pratique : initier la transition IV→oral dès stabilisation clinique dans les infections ostéo-articulaires pédiatriques non compliquées — 24 études (N=7881) valident cette stratégie.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-03-30"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": 7881,
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie-orthopédie"
        }
    },
    {
        "candidate_id": "3a5d9a95-ee1d-47a5-ba7d-8ac31c177063",
        "score": 7, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Durée courte antibiotiques OMA enfant : revue systématique",
            "resume": "Revue systématique (MEDLINE/Embase/CENTRAL jusqu'en février 2024) comparant les traitements courts (5j) vs longs (8-10j) d'antibiotiques dans l'otite moyenne aiguë de l'enfant. Non-infériorité des traitements courts confirmée pour l'efficacité clinique.",
            "impact_pratique": "En pratique : prescrire 5 jours d'amoxicilline dans l'OMA non compliquée de l'enfant >2 ans — les preuves soutiennent la réduction de durée sans perte d'efficacité clinique.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-28"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled RCTs",
            "clinical_maturity": "practice-defining",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "ORL-infectiologie"
        }
    },
    {
        "candidate_id": "17d51938-65e5-47ab-95e8-9bc3c906cdb6",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Test moléculaire rapide SGA angine : impact antibiothérapie Berlin",
            "resume": "Essai cluster randomisé en cross-over (25 cabinets pédiatriques, Berlin, déc. 2023 – mai 2024) évaluant l'impact d'un test moléculaire rapid point-of-care (mPOC) pour le SGA sur les prescriptions antibiotiques dans les angines pédiatriques.",
            "impact_pratique": "En pratique : le test moléculaire rapide SGA permet de mieux guider l'antibiothérapie dans les angines — plus précis que les TDR classiques pour réduire les prescriptions inappropriées.",
            "nature": "ETUDE",
            "date_publication": "2026-03-10"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": "25 pediatric offices Berlin cluster RCT",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "ORL-infectiologie"
        }
    },
    {
        "candidate_id": "0ea38443-6476-42f1-892d-97a22c8ed6cb",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Pneumonie réfractaire M. pneumoniae enfant : 53 études (N=35 275)",
            "resume": "Méta-analyse de 53 études (N=35 275 enfants) sur la pneumonie réfractaire à M. pneumoniae (rMPP). Prévalence globale établie, facteurs de risque identifiés (résistance macrolides, âge scolaire, infiltrat lobaire), et précision des modèles prédictifs pour la reconnaissance précoce.",
            "impact_pratique": "En pratique : suspecter une rMPP devant une pneumonie à M. pneumoniae évoluant >7 jours sous macrolide — basculer précocement vers doxycycline (>8 ans) ou quinolone selon les facteurs de risque.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-02-21"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": 35275,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie-pneumologie"
        }
    },
    {
        "candidate_id": "3aa303b5-36c4-4049-8cac-a20fbc5e1147",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Insuline basale précoce pendant IV dans l'ACR pédia : méta-analyse GRADE",
            "resume": "Méta-analyse GRADE (PROSPERO CRD420251155626) évaluant l'initiation précoce de l'insuline basale (glargine/détémir en overlap ≥4h avec l'insuline IV) dans l'acidocétose diabétique pédiatrique. Critère principal : délai de résolution de l'acidocétose. Évalue le rapport bénéfice/risque hypoglycémique.",
            "impact_pratique": "En pratique : l'insuline basale précoce en overlap avec l'insuline IV peut réduire la durée de l'ACR — évaluer les résultats finaux avant d'adapter les protocoles institutionnels.",
            "nature": "META-ANALYSE",
            "date_publication": "2025-11-26"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": "pooled pediatric DKA studies",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "endocrinologie-urgences"
        }
    },
    {
        "candidate_id": "f758956d-d4fa-4d1e-b737-580f3047be19",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Convulsions fébriles COVID Omicron : méta-analyse 36 études (N=82 591)",
            "resume": "Méta-analyse de 36 études (N=82 591 enfants COVID) évaluant l'incidence des convulsions fébriles selon le variant SARS-CoV-2. L'incidence est plus élevée en période Omicron qu'en pré-Omicron, particulièrement chez les enfants hospitalisés.",
            "impact_pratique": "En pratique : informer les parents que le risque de convulsion fébrile est accru avec COVID-Omicron — éduquer sur la conduite à tenir à domicile et les seuils d'alerte.",
            "nature": "META-ANALYSE",
            "date_publication": "2026-01-31"
        },
        "evidence_json": {
            "study_design": "meta-analysis",
            "n_patients": 82591,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": True,
            "pediatric_domain": "neurologie-infectiologie"
        }
    },
    {
        "candidate_id": "5aba2e24-d458-487c-978e-ac7e00e00799",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Fondoscopie avant PL méningite pédiatrique : 1742 enfants, 15 DEPU",
            "resume": "Cohorte rétrospective multicentrique (15 urgences pédiatriques, N=1742, médiane 4,6 ans, 2018-2023). Méningite bactérienne : 3,2%. Papilloedème : 2,8%, tous ont bénéficié d'une PL sans complication. Mais 3 enfants avec fond d'œil normal avaient un CT anormal (2 abcès, 1 tumeur).",
            "impact_pratique": "En pratique : un fond d'œil normal n'exclut pas une lésion intracrânienne — en cas de méningite suspecte avec signes focaux ou ACSOS, réaliser le scanner avant la PL quel que soit le fond d'œil.",
            "nature": "ETUDE",
            "date_publication": "2025-11-14"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": 1742,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": True,
            "pediatric_domain": "neurologie-urgences"
        }
    },
    {
        "candidate_id": "3ff1711d-0053-4755-8bd0-67aee31ed89e",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "RSV sévère enfants 12-23 mois : facteurs risque, 11 centres (2017-2021)",
            "resume": "Étude multicentrique rétrospective (11 centres, 2017-2021) sur les enfants 12-23 mois hospitalisés pour RSV. Les facteurs de risque (prématurité <37 SA, cardiopathie congénitale, BPDC, trisomie 21) sont associés à une hospitalisation prolongée et à une admission en PICU, dans l'ère d'expansion de l'immunoprophylaxie longue durée.",
            "impact_pratique": "En pratique : à l'ère du nirsévimab, identifier les enfants 12-23 mois avec facteurs de risque dès la 2ème saison RSV pour adapter l'immunoprophylaxie si disponible.",
            "nature": "ETUDE",
            "date_publication": "2025-11-27"
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": "11 medical centers 2017-2021",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie-pneumologie"
        }
    },
    {
        "candidate_id": "0eb64262-7e1a-4191-9161-e08bb5b20969",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "Rougeole pédiatrique Turquie 2023 : prédicteurs sévérité, 34 centres",
            "resume": "Cohorte rétrospective multicentrique (34 centres Turquie, 2023) de tous les enfants ≤18 ans hospitalisés avec rougeole WHO-confirmée. Description des complications, de la sévérité et de l'impact du statut vaccinal. Contexte d'épidémie mondiale croissante depuis 2022, pic en 2024.",
            "impact_pratique": "En pratique : devant tout enfant non ou incomplètement vacciné avec fièvre et éruption, évoquer la rougeole et isoler immédiatement — vérifier systématiquement le statut vaccinal ROR.",
            "nature": "ETUDE",
            "date_publication": "2025-10-29"
        },
        "evidence_json": {
            "study_design": "registry",
            "n_patients": "34 centers Turkey 2023",
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": True,
            "pediatric_domain": "infectiologie-preventif"
        }
    },
    {
        "candidate_id": "eaedc4b5-c7fe-4414-920a-5efeed41c7cc",
        "score": 5, "source_type": "innovation", "categorie": "clinique",
        "tri_json": {
            "titre_court": "M. pneumoniae post-COVID : phénotypes, sévérité, 400 enfants hospitalisés",
            "resume": "Cohorte rétrospective multicentrique (20 centres tertiaires Turquie, N=400, juillet 2021-juillet 2024) sur M. pneumoniae hospitalisé en ère post-COVID. Caractérisation des formes pulmonaires vs extrapulmonaires, facteurs de risque de forme critique, et impact de la résistance aux macrolides en période de résurgence.",
            "impact_pratique": "En pratique : en ère post-COVID, surveiller les signes extrapulmonaires de M. pneumoniae et les facteurs de risque de forme critique — anticiper l'escalade thérapeutique (doxycycline, quinolone) si résistance aux macrolides.",
            "nature": "ETUDE",
            "date_publication": "2025-11-20"
        },
        "evidence_json": {
            "study_design": "cohort",
            "n_patients": 400,
            "clinical_maturity": "confirmatory",
            "actionability_horizon": "immediate",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "infectiologie-pneumologie"
        }
    },
    {
        "candidate_id": "3a35dae8-1797-42fd-ace4-d9d4791ea650",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "Sevrage HFNC bronchiolite sévère piloté par infirmier : RCT",
            "resume": "RCT dans deux PICU tertiaires évaluant un protocole de sevrage HFNC infirmier-piloté (score Wang WBSS + index ROX) vs soins standard pour la bronchiolite sévère de 1-24 mois. Critère principal : durée totale de HFNC.",
            "impact_pratique": "En pratique : un protocole de sevrage HFNC structuré piloté par les infirmières (WBSS + ROX index) réduit la durée d'OHD en bronchiolite sévère — à adopter pour standardiser la pratique.",
            "nature": "ETUDE",
            "date_publication": "2026-03-23"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": "2 PICU bronchiolitis season RCT",
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie-reanimation"
        }
    },
    {
        "candidate_id": "6e1e0f48-1f56-4ab0-8633-a619fa6ed86c",
        "score": 5, "source_type": "innovation", "categorie": "therapeutique",
        "tri_json": {
            "titre_court": "HFNC bronchiolite : débits 1, 2, 3 L/kg/min comparés — RCT (N=90)",
            "resume": "RCT comparant trois débits de HFNC (1, 2, 3 L/kg/min) dans la bronchiolite modérée à sévère de l'enfant 1-12 mois (N=90, 30/groupe). Premier essai comparant directement ces trois débits pour identifier le débit optimal selon les critères AAP.",
            "impact_pratique": "En pratique : démarrer à 2 L/kg/min et ajuster selon la réponse clinique — cet essai est le premier à comparer les trois débits standards et guidera la recommandation.",
            "nature": "ETUDE",
            "date_publication": "2025-12-23"
        },
        "evidence_json": {
            "study_design": "rct",
            "n_patients": 90,
            "clinical_maturity": "preliminary",
            "actionability_horizon": "1-3y",
            "paradigm_shift": False,
            "safety_signal": False,
            "pediatric_domain": "pneumologie"
        }
    },
]

print(f"Total items à insérer : {len(ITEMS)}")

inserted = 0
skipped = 0
errors = []

for item in ITEMS:
    cid = item["candidate_id"]
    # Vérif doublon
    cur.execute(
        "SELECT id FROM items WHERE candidate_id=%s AND specialty_slug=%s",
        (cid, SLUG)
    )
    if cur.fetchone():
        print(f"  SKIP (doublon) : {cid[:8]}")
        skipped += 1
        continue

    # Fix titre_court manquant dans MeMed BV (typo)
    tj = item["tri_json"].copy()
    if "titre_cout" in tj:
        del tj["titre_cout"]

    try:
        lecture_json = {
            "texte_long": tj.get("resume", ""),
            "points_cles": [tj.get("impact_pratique", "")],
            "references": []
        }
        cur.execute(
            """INSERT INTO items
               (id, candidate_id, specialty_slug, score_density, source_type, categorie,
                tri_json, evidence_json, llm_model, review_status, audience, lecture_json,
                llm_created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (
                str(uuid.uuid4()),
                cid,
                SLUG,
                item["score"],
                item["source_type"],
                item["categorie"],
                json.dumps(tj, ensure_ascii=False),
                json.dumps(item["evidence_json"], ensure_ascii=False),
                "manuel",
                "PENDING",
                "SPECIALITE",
                json.dumps(lecture_json, ensure_ascii=False),
            )
        )
        inserted += 1
        print(f"  OK : {cid[:8]} — {tj.get('titre_court','?')[:60]}")
    except Exception as e:
        errors.append((cid[:8], str(e)))
        print(f"  ERREUR : {cid[:8]} — {e}")

conn.commit()
print(f"\n=== Résultat ===")
print(f"Insérés  : {inserted}")
print(f"Skippés  : {skipped}")
print(f"Erreurs  : {len(errors)}")
for e in errors:
    print(f"  {e[0]}: {e[1]}")
conn.close()
