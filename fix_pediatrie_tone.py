#!/usr/bin/env python3
"""Correction du ton rédactionnel des 50 items pédiatrie — style journal médical spécialisé."""
import os, json
from dotenv import load_dotenv
load_dotenv()
import psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur = conn.cursor()

# Format : (candidate_id_prefix, nouveau tri_json complet)
CORRECTIONS = [
    # ── JAMA PEDIATRICS ──────────────────────────────────────────────────────
    ("775462cd", {
        "titre_court": "Nirsévimab en vie réelle : efficacité confirmée, saison 2024-25",
        "resume": "Durant la saison RSV 2024-25, la première saison où nirsévimab et vaccin RSV maternel ont été largement disponibles aux États-Unis, une surveillance en population (7 centres pédiatriques, enfants <2 ans, design test-négatif) confirme l'efficacité élevée des deux produits contre les infections respiratoires aiguës médicalement assistées. Ces données en vie réelle sont la première évaluation d'impact à grande échelle depuis la généralisation de l'immunoprophylaxie.",
        "impact_pratique": "En pratique : la saison 2024-25 valide l'efficacité du nirsévimab hors essai — la recommandation systématique chez tous les nourrissons éligibles avant l'entrée en saison est pleinement justifiée.",
        "nature": "ETUDE",
        "date_publication": "2026-03-01"
    }),
    ("a11bc511", {
        "titre_court": "Nirsévimab et hospitalisations pour LRTI : méta-analyse post-AMM",
        "resume": "Depuis sa commercialisation en 2023, le nirsévimab fait l'objet d'un suivi en vie réelle dont cette méta-analyse (MEDLINE/Embase/medRxiv, jusqu'en juin 2025) dresse le bilan pour les hospitalisations et passages aux urgences pour infections respiratoires basses à RSV chez le nourrisson. Les données observationnelles convergeantes confirment une protection substantielle, cohérente avec les résultats des essais pivots MELODY et HARMONIE.",
        "impact_pratique": "En pratique : le bénéfice du nirsévimab sur les hospitalisations est désormais attesté en conditions réelles d'utilisation — l'argumentaire clinique pour sa prescription systématique est solide.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-01"
    }),
    ("8c0c7bee", {
        "titre_court": "GLP-1 RA chez l'enfant obèse ou diabétique : première méta-analyse",
        "resume": "L'obésité touche un enfant sur cinq et le diabète de type 2 pédiatrique progresse, mais les options pharmacologiques validées restent rares. Cette méta-analyse (RCTs jusqu'en février 2025) établit que les agonistes du récepteur GLP-1 — semaglutide et liraglutide principalement — réduisent significativement l'IMC et l'HbA1c chez les moins de 18 ans avec un profil de tolérance acceptable. C'est la première synthèse systématique de cette classe thérapeutique en pédiatrie.",
        "impact_pratique": "En pratique : pour l'obésité sévère ou le DT2 pédiatrique résistant aux mesures hygiéno-diététiques, les GLP-1 RA constituent désormais une option pharmacologique de seconde ligne fondée sur des preuves — à discuter en réunion multidisciplinaire dès l'adolescence.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-12-01"
    }),
    ("71d6de37", {
        "titre_court": "Boucle fermée hybride et DT1 de l'enfant : méta-analyse de 2017 à 2025",
        "resume": "Pour les 6-18 ans vivant avec un diabète de type 1, les systèmes de délivrance automatisée d'insuline (AID/boucle fermée) s'imposent comme la stratégie de référence. Cette méta-analyse de RCTs en ambulatoire (MEDLINE/Embase/CINAHL/Cochrane, 2017-2025) le confirme : amélioration significative du temps en cible (TIR) et de l'HbA1c par rapport à tout traitement conventionnel, sans surrisque hypoglycémique.",
        "impact_pratique": "En pratique : lors du choix d'un dispositif pour un enfant ou adolescent avec DT1, les systèmes en boucle fermée hybride doivent être présentés en première option — la démonstration de supériorité est désormais robuste.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-11-01"
    }),
    ("6a68a8f5", {
        "titre_court": "BRUE du nourrisson : pronostic, facteurs de risque et utilité des bilans",
        "resume": "Depuis l'introduction du concept de BRUE par l'AAP en 2016, la pratique clinique reste hétérogène faute de données synthétisées. Cette méta-analyse (PubMed/Embase/Cochrane, 2016-juillet 2025) répond aux trois questions qui comptent : la fréquence d'un diagnostic sous-jacent grave est d'environ 4%, la mortalité à 3 mois reste inférieure à 1%, et le rendement diagnostique des explorations extensives est faible en l'absence de facteurs de risque identifiés.",
        "impact_pratique": "En pratique : la stratification AAP 2016 (bas risque) est validée par cette synthèse — les bilans invasifs systématiques ne sont pas justifiés chez le nourrisson sans facteur de risque après un premier épisode de BRUE.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-03-01"
    }),
    ("19378ee2", {
        "titre_court": "Interventions communautaires et tension artérielle chez l'enfant",
        "resume": "La prévalence de l'hypertension pédiatrique augmente, portée par l'épidémie d'obésité, mais les interventions médicamenteuses restent peu adaptées à cet âge. Cette revue systématique des programmes scolaires et communautaires chez les 3-18 ans montre qu'une action combinée sur l'alimentation et l'activité physique entraîne une réduction modeste mais reproductible de la TA systolique, particulièrement dans les populations à risque.",
        "impact_pratique": "En pratique : orienter les enfants avec TA limite vers des programmes multidisciplinaires en milieu scolaire — des effets tensionnels mesurables peuvent être obtenus sans recours médicamenteux.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-01"
    }),
    ("67552b59", {
        "titre_court": "Survie à 22-23 semaines : leçons de 11 réseaux néonataux internationaux",
        "resume": "La prise en charge active des grands prématurés nés à 22-23 SA progresse dans de nombreux pays, mais les données restent fragmentées. Cette collaboration de 11 réseaux néonataux internationaux (INEN) révèle une variabilité considérable des taux de survie — de 20 à 70% selon les réseaux — avec des morbidités majeures persistantes. Ces chiffres, issus du terrain et non de centres d'excellence isolés, sont les références qui devraient nourrir le conseil prénatal.",
        "impact_pratique": "En pratique : pour structurer un conseil prénatal à 22-23 SA, ces données internationales complètent les chiffres locaux — la survie est possible mais variable selon les ressources, et le pronostic neurologique reste la question centrale.",
        "nature": "ETUDE",
        "date_publication": "2025-11-01"
    }),
    ("8ef904bd", {
        "titre_court": "Hydrocortisone préventive et dysplasie bronchopulmonaire : que devient l'enfant à l'âge scolaire ?",
        "resume": "L'hydrocortisone préventive reste débattue en réanimation néonatale, faute de données de suivi à long terme. Cet essai du réseau NRN comble cette lacune en rapportant les résultats neurodéveloppementaux à l'âge scolaire des prématurés traités dans l'essai original contre placebo. La décision en NICU ne peut plus faire l'économie de cette dimension longitudinale.",
        "impact_pratique": "En pratique : les données de suivi scolaire sont désormais disponibles pour les équipes qui utilisent l'hydrocortisone préventive en NICU — évaluer le rapport bénéfice pulmonaire / risque neurodéveloppemental à la lumière de ces résultats.",
        "nature": "ETUDE",
        "date_publication": "2026-02-01"
    }),
    ("832d1e8d", {
        "titre_court": "Dépistage des IST aux urgences : les adolescents ne consultent pas ailleurs",
        "resume": "Aux États-Unis, les adolescents représentent près de la moitié des 2,5 millions d'IST diagnostiquées chaque année, et les urgences constituent souvent leur seul point de contact médical. Cette étude comparative évalue trois stratégies de dépistage gonorrhée/chlamydia (soins habituels, ciblé, universel) dans ce contexte : le dépistage opportuniste détecte des cas que la pratique habituelle ignore.",
        "impact_pratique": "En pratique : proposer un dépistage gonorrhée/chlamydia aux adolescents sexuellement actifs à chaque passage aux urgences, quel que soit le motif — c'est souvent la seule occasion de les atteindre.",
        "nature": "ETUDE",
        "date_publication": "2025-12-01"
    }),
    ("311afc49", {
        "titre_court": "Drépanocytose aux urgences : chaque heure de délai d'opioïde compte",
        "resume": "Les recommandations sur la drépanocytose préconisent depuis longtemps une administration rapide des opioïdes lors des crises douloureuses, mais les preuves d'impact clinique manquaient. Cette étude multisite PECARN démontre que la rapidité d'administration de plusieurs doses d'opioïdes aux urgences est associée à une réduction mesurable du risque d'hospitalisation chez l'enfant drépanocytaire.",
        "impact_pratique": "En pratique : dans une crise drépanocytaire, le premier opioïde doit être administré dans les 60 minutes — le délai de prise en charge est un déterminant direct du risque d'hospitalisation.",
        "nature": "ETUDE",
        "date_publication": "2025-11-01"
    }),
    # ── PEDIATRICS GUIDELINES ────────────────────────────────────────────────
    ("b27b7e8c", {
        "titre_court": "Réanimation néonatale : les nouvelles recommandations AHA/AAP 2025",
        "resume": "Les recommandations AHA/AAP pour la réanimation néonatale en salle de naissance ont été actualisées pour 2025, intégrant les dernières données ILCOR. Les évolutions majeures portent sur le clampage différé du cordon (≥60 secondes recommandé par défaut), la priorité aux soins peau-à-peau, et une thermorégulation proactive dès la naissance. Elles s'appliquent à tous les professionnels présents en salle de naissance.",
        "impact_pratique": "En pratique : revoir les protocoles de salle de naissance selon les recommandations 2025 — le clampage différé ≥60 secondes devient la norme, sauf urgence identifiée.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-01-01"
    }),
    ("3f9973a0", {
        "titre_court": "BLS pédiatrique AHA/AAP 2025 : première refonte depuis 2020",
        "resume": "Cinq ans après la précédente mise à jour, les recommandations AHA/AAP pour la réanimation de base (BLS) pédiatrique ont été entièrement révisées pour 2025 à partir des évaluations structurées de l'ILCOR. Elles portent sur les séquences de RCP, l'utilisation du DEA en pédiatrie, et la chaîne de survie. Document de référence pour toute formation en pédiatrie d'urgence.",
        "impact_pratique": "En pratique : les formations BLS pédiatriques doivent être mises à jour selon les recommandations 2025 — revoir les algorithmes DEA et les séquences de RCP pour toutes les équipes qui prennent en charge l'enfant.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-01-01"
    }),
    ("35f85141", {
        "titre_court": "Prévention du RSV 2025 : le nirsévimab en première ligne selon l'AAP",
        "resume": "L'AAP a mis à jour ses recommandations de prévention du RSV pour 2025, intégrant les données des saisons post-commercialisation du nirsévimab. Le nirsévimab devient l'immunoprophylaxie préférée pour tous les nourrissons de moins de 8 mois entrant dans leur première saison RSV. Le palivizumab est désormais réservé aux populations à haut risque spécifiquement définies.",
        "impact_pratique": "En pratique : proposer systématiquement le nirsévimab à tous les nourrissons <8 mois avant la saison RSV — sa supériorité logistique et son profil d'efficacité justifient qu'il remplace le palivizumab en première intention.",
        "nature": "RECOMMANDATION",
        "date_publication": "2025-11-01"
    }),
    ("ad18053a", {
        "titre_court": "PALS 2025 : les nouvelles recommandations AHA/AAP en réanimation avancée",
        "resume": "Les recommandations 2025 AHA/AAP pour le support avancé des fonctions vitales pédiatriques (PALS) actualisent les algorithmes de prise en charge de l'arrêt cardio-respiratoire, du choc, de l'état de mal épileptique et des voies aériennes, de la naissance à 18 ans. Document de référence pour les services d'urgences pédiatriques, les PICU et toute équipe de soins critiques.",
        "impact_pratique": "En pratique : mettre à jour les protocoles PALS institutionnels selon les recommandations 2025 — les algorithmes de prise en charge du choc et de l'ACR pédiatrique ont évolué.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-01-01"
    }),
    ("fa9e39df", {
        "titre_court": "Grippe 2025-2026 : recommandations AAP vaccins et antiviraux chez l'enfant",
        "resume": "Chaque année, l'AAP actualise ses recommandations pour la prévention et le traitement de la grippe chez l'enfant. Pour 2025-2026, elles confirment la vaccination annuelle universelle dès 6 mois sans contre-indication, précisent les formulations disponibles, et détaillent les indications de l'oseltamivir et du baloxavir, notamment pour les enfants immunodéprimés ou à risque de forme grave.",
        "impact_pratique": "En pratique : vacciner chaque enfant ≥6 mois dès la disponibilité des vaccins, et prescrire l'oseltamivir précocement chez les enfants à risque devant tout tableau grippal — sans attendre la confirmation virologique.",
        "nature": "RECOMMANDATION",
        "date_publication": "2025-12-01"
    }),
    ("20f73e85", {
        "titre_court": "Allergie alimentaire à l'école : le pédiatre au centre du dispositif",
        "resume": "L'allergie alimentaire concerne jusqu'à 10% des enfants scolarisés et une anaphylaxie survient dans une école sur quinze chaque année. L'AAP actualise son rapport clinique de 2010 sur la gestion de l'allergie alimentaire en milieu scolaire, en précisant le rôle du pédiatre dans la coordination des plans d'urgence individualisés, la formation des équipes éducatives et la prescription des dispositifs d'urgence.",
        "impact_pratique": "En pratique : rédiger un plan d'urgence individualisé pour chaque enfant allergique scolarisé, inclure la prescription d'adrénaline auto-injectable et s'assurer de sa transmission à l'établissement.",
        "nature": "RECOMMANDATION",
        "date_publication": "2025-12-01"
    }),
    ("f62a686b", {
        "titre_court": "AAP 2025 : recommandations vaccins COVID pour nourrissons, enfants, adolescents",
        "resume": "L'AAP met à jour ses recommandations pour la vaccination COVID-19 chez les nourrissons, enfants et adolescents, intégrant les formulations adaptées aux variants circulants en 2025. Le document précise les indications selon l'âge, le statut immunitaire et les facteurs de risque de forme grave, en distinguant les populations pour lesquelles la vaccination est prioritaire.",
        "impact_pratique": "En pratique : appliquer le schéma vaccinal COVID-19 AAP 2025 aux enfants éligibles, en priorité pour les enfants immunodéprimés ou porteurs de pathologies à risque de forme sévère.",
        "nature": "RECOMMANDATION",
        "date_publication": "2025-11-01"
    }),
    ("ce474b73", {
        "titre_court": "Calendrier vaccinal pédiatrique américain 2026 : les nouveautés",
        "resume": "Le calendrier vaccinal recommandé pour les enfants et adolescents américains est actualisé chaque année par l'AAP, l'ACIP et l'AAFP. L'édition 2026 intègre les nouvelles recommandations pour le RSV (nirsévimab), la grippe (formulations 2025-26), et les mises à jour du calendrier de rattrapage. Document de référence pour tout pédiatre assurant le suivi vaccinal.",
        "impact_pratique": "En pratique : consulter le calendrier 2026 à chaque visite de suivi pour vérifier le statut vaccinal et identifier les retards — la mise à jour annuelle porte sur plusieurs vaccins simultanément.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-03-01"
    }),
    ("aaa30750", {
        "titre_court": "Écosystèmes numériques et enfants : l'AAP dépasse la notion de temps d'écran",
        "resume": "Le rapport technique AAP 2025 sur les écosystèmes numériques reconnaît que la notion de « temps d'écran » ne suffit plus à décrire la réalité des familles face à l'IA, aux réseaux sociaux, aux jeux vidéo et aux objets connectés. Il propose une approche centrée sur la qualité et le contexte des usages plutôt que sur leur durée, et fournit aux pédiatres un cadre d'évaluation et de conseil adapté à ces environnements numériques complexes.",
        "impact_pratique": "En pratique : lors des bilans annuels, explorer la qualité des usages numériques familiaux plutôt que le seul temps d'écran — et accompagner les familles vers un plan d'utilisation réfléchi.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-02-01"
    }),
    ("5d0e2d22", {
        "titre_court": "Cassure de courbe pondérale et précarité : l'AAP fait le point",
        "resume": "Le rapport technique AAP analyse la relation entre le statut socio-économique (SES) et la cassure de courbe staturo-pondérale (faltering weight) chez les moins de 5 ans, et compare l'efficacité des différentes modalités de prise en charge. Le SES bas est un facteur de risque confirmé ; les approches multidisciplinaires intégrant diététicien, travail social et suivi médical sont les plus efficaces.",
        "impact_pratique": "En pratique : toute cassure de courbe doit être resituée dans son contexte socio-économique — une orientation multidisciplinaire incluant le travail social est plus efficace qu'une prise en charge médicale isolée.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-03-16"
    }),
    ("c30524e9", {
        "titre_court": "Chorée de Sydenham : 88 recommandations de consensus pour la pratique",
        "resume": "La chorée de Sydenham est sous-diagnostiquée, sa prise en charge hétérogène. Un panel international de 27 experts — neurologues, psychiatres et représentants de patients — a conduit un processus Delphi aboutissant à 88 recommandations consensuelles sur le diagnostic (chorée et hypotonie comme signes clés), le dépistage des troubles comportementaux et psychiatriques associés, et le traitement. C'est la première recommandation internationale entièrement dédiée à cette affection.",
        "impact_pratique": "En pratique : évoquer une chorée de Sydenham devant tout mouvement anormal chez l'enfant avec antécédent streptococcique — le bilan inclut échocardiographie et ASLO ; les recommandations 2025 guident le traitement.",
        "nature": "RECOMMANDATION",
        "date_publication": "2025-12-01"
    }),
    # ── PEDIATRICS ───────────────────────────────────────────────────────────
    ("9e04b25e", {
        "titre_court": "Modulateurs CFTR et diabète mucoviscidosien : vers une rémission glycémique ?",
        "resume": "Le diabète lié à la mucoviscidose (CFRD) complique jusqu'à 50% des adultes atteints et aggrave leur pronostic respiratoire. Cette méta-analyse évalue l'impact des modulateurs CFTR (élexacaftor-tézacaftor-ivacaftor principalement) sur l'équilibre glycémique dans la mucoviscidose. Les modulateurs améliorent significativement le contrôle glycémique et semblent réduire la progression vers le CFRD — un changement de paradigme dans la prise en charge métabolique.",
        "impact_pratique": "En pratique : chez tout patient mucoviscidosique sous modulateurs CFTR, réévaluer régulièrement la stratégie de surveillance et de traitement du CFRD — une amélioration glycémique est attendue, pouvant permettre de réduire ou d'arrêter l'insulinothérapie.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-01"
    }),
    ("c7f6d83a", {
        "titre_court": "Grippe chez l'enfant avec comorbidité : la vaccination reste aussi efficace",
        "resume": "Les enfants porteurs de pathologies sous-jacentes sont prioritaires pour la vaccination antigrippale, mais l'efficacité vaccinale dans ce groupe reste mal documentée. Cette analyse de surveillance aux urgences américaines répond à la question : la vaccination contre la grippe protège aussi bien les enfants avec comorbidités que les enfants sains contre les formes confirmées, justifiant de ne pas relâcher l'effort de couverture dans ces populations.",
        "impact_pratique": "En pratique : ne pas hésiter à vacciner les enfants avec comorbidités même s'ils paraissent « fragiles » — l'efficacité vaccinale est préservée et le bénéfice est au moins aussi important que chez l'enfant sain.",
        "nature": "ETUDE",
        "date_publication": "2026-02-01"
    }),
    ("31746c98", {
        "titre_court": "Test MeMed BV dans les infections pédiatriques : viral ou bactérien en 15 minutes",
        "resume": "Face à un enfant fébrile dont l'origine infectieuse reste incertaine, le test MeMed BV — qui mesure trois protéines de l'hôte (TRAIL, IP-10, CRP) — aide à orienter la décision clinique. Une étude pragmatique menée dans des centres de soins urgents montre que le test modifie les décisions de référence et de prescription antibiotique dans environ un tiers des cas d'incertitude diagnostique.",
        "impact_pratique": "En pratique : le test MeMed BV s'intègre utilement dans les situations d'incertitude diagnostic viral/bactérien aux urgences pédiatriques — son adoption progressive peut réduire les prescriptions antibiotiques inappropriées.",
        "nature": "ETUDE",
        "date_publication": "2026-01-01"
    }),
    ("5655b323", {
        "titre_court": "Allergie à l'arachide : les pédiatres appliquent encore mal la recommandation de 2017",
        "resume": "Les recommandations américaines de 2017 préconisent l'introduction précoce de l'arachide dès 4-6 mois chez les nourrissons à risque (eczéma, allergie à l'œuf) pour prévenir l'allergie. L'essai iREACH, randomisé en cluster auprès de cabinets pédiatriques, révèle que l'adhérence à cette recommandation reste insuffisante des années après sa publication, compromettant la prévention à grande échelle.",
        "impact_pratique": "En pratique : recommander systématiquement et explicitement l'introduction de l'arachide dès 4-6 mois aux nourrissons avec eczéma ou allergie à l'œuf — cette fenêtre préventive est encore trop souvent manquée.",
        "nature": "ETUDE",
        "date_publication": "2025-11-01"
    }),
    ("f3fe4d72", {
        "titre_court": "Commotion cérébrale avant 6 ans : des symptômes qui persistent au-delà d'un an",
        "resume": "Les commotions cérébrales chez le jeune enfant sont fréquentes mais peu étudiées en dessous de 6 ans. Cette cohorte multicentrique (urgences Canada et États-Unis, enfants 6 mois-6 ans) documente pour la première fois la fréquence des symptômes persistants à un an (PSaC) dans cette tranche d'âge et identifie les facteurs prédicteurs — données manquantes jusqu'alors et attendues pour guider le suivi.",
        "impact_pratique": "En pratique : avertir les parents dès la consultation initiale que des symptômes peuvent persister au-delà d'un mois chez le jeune enfant après une commotion — un suivi à 4 semaines est justifié pour identifier les facteurs de risque.",
        "nature": "ETUDE",
        "date_publication": "2026-02-01"
    }),
    ("97a6572e", {
        "titre_court": "Bronchiolite en soins primaires : la déprescription des bronchodilatateurs est réalisable",
        "resume": "Malgré des recommandations claires déconseillant les bronchodilatateurs dans la bronchiolite, leur utilisation reste répandue en soins primaires. Un programme d'amélioration qualité dans un large réseau pédiatrique a ramené le taux d'utilisation de 24% à 15% en 12 mois, sans augmenter les stéroïdes ni générer de signaux de sécurité — la preuve que la déprescription est possible à grande échelle.",
        "impact_pratique": "En pratique : ne pas prescrire de bronchodilatateur dans la bronchiolite légère à modérée, y compris en libéral — une démarche éducative auprès des familles suffit à gérer leur attente thérapeutique.",
        "nature": "ETUDE",
        "date_publication": "2025-11-01"
    }),
    # ── ARCHIVES OF DISEASE IN CHILDHOOD ─────────────────────────────────────
    ("a9a78a2c", {
        "titre_court": "Règle PECARN pour le nourrisson fébrile <60 jours : validée en Europe",
        "resume": "La règle PECARN, développée aux États-Unis pour identifier les nourrissons fébriles de moins de 60 jours à faible risque d'infection bactérienne sévère (IBS), est ici validée pour la première fois dans des cohortes européennes (MOFICHE, 12 urgences pédiatriques en 8 pays ; Suède, 4 centres). La règle conserve une sensibilité acceptable, et la CRP peut remplacer la procalcitonine lorsque celle-ci est indisponible.",
        "impact_pratique": "En pratique : la règle PECARN peut être appliquée dans les urgences pédiatriques européennes pour limiter les hospitalisations et ponctions lombaires inutiles chez les nourrissons fébriles <60 jours — avec CRP comme alternative à la procalcitonine.",
        "nature": "ETUDE",
        "date_publication": "2026-03-19"
    }),
    ("31b30b09", {
        "titre_court": "Magnésium IV dans l'asthme aigu sévère de l'enfant : réduction de 30% des hospitalisations",
        "resume": "Le rôle du sulfate de magnésium intraveineux dans l'asthme aigu pédiatrique sévère était insuffisamment documenté. Cette méta-analyse de 9 RCTs (N=473) clôt le débat : en add-on aux SABA et corticoïdes, il réduit le taux d'hospitalisation de 30% (RR=0,70 ; IC95% 0,54–0,90) et divise par six le recours à la ventilation non invasive (RR=0,17 ; p=0,003).",
        "impact_pratique": "En pratique : dans tout asthme aigu sévère ne répondant pas aux bronchodilatateurs aux urgences, le magnésium IV s'impose en deuxième ligne — son efficacité est maintenant la mieux documentée parmi les traitements adjuvants.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-11-19"
    }),
    ("4beccdca", {
        "titre_court": "HFNC en bronchiolite du nourrisson : ce que disent les guidelines en 2024",
        "resume": "L'oxygénothérapie haut débit (HFNC) s'est largement imposée dans la bronchiolite du nourrisson, mais les pratiques d'initiation, de surveillance et de sevrage varient considérablement d'un centre à l'autre. Cette revue systématique des guidelines nationales et internationales applicables aux 1-23 mois fournit une synthèse opérationnelle des recommandations disponibles en 2024, permettant aux équipes d'harmoniser leurs protocoles.",
        "impact_pratique": "En pratique : utiliser cette synthèse pour standardiser les protocoles HFNC en bronchiolite dans votre unité — les critères d'initiation et de sevrage sont ceux sur lesquels la variabilité est la plus forte.",
        "nature": "RECOMMANDATION",
        "date_publication": "2026-03-19"
    }),
    ("d8c85d17", {
        "titre_court": "Ipratropium inhalé dans l'asthme aigu pédiatrique : méta-analyse actualisée",
        "resume": "L'ipratropium bromide inhalé en association aux bêta-2 agonistes à courte durée d'action est utilisé depuis des décennies dans les crises d'asthme pédiatriques, mais les données synthétisées manquaient. Cette méta-analyse de RCTs (jusqu'en juillet 2024) consolide son bénéfice sur la morbidité, l'escalade thérapeutique et la durée d'hospitalisation, dans les exacerbations modérées à sévères.",
        "impact_pratique": "En pratique : l'association SABA + ipratropium reste justifiée dans les crises d'asthme modérées à sévères de l'enfant — cette méta-analyse renforce l'argumentaire pour maintenir l'ipratropium dans les protocoles d'urgence.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-19"
    }),
    ("3ac54797", {
        "titre_court": "Aminophylline IV dans l'asthme sévère de l'enfant : efficace mais à surveiller",
        "resume": "L'aminophylline intraveineuse reste utilisée comme traitement de recours dans l'asthme aigu sévère pédiatrique, malgré une fenêtre thérapeutique étroite. Cette méta-analyse exhaustive (1966-mai 2024, MEDLINE/Embase/Cochrane) confirme son efficacité sur la fonction respiratoire et le taux d'hospitalisation en add-on au traitement de première ligne, mais souligne un risque d'effets indésirables (nausées, arythmies) qui impose une surveillance étroite.",
        "impact_pratique": "En pratique : réserver l'aminophylline IV aux asthmes sévères résistants au traitement de première ligne et au magnésium — son bénéfice est réel mais sa marge thérapeutique étroite requiert un monitoring continu.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-11-19"
    }),
    ("865abae2", {
        "titre_court": "Asthme sévère réfractaire : quel traitement de deuxième ligne choisir ?",
        "resume": "Lorsque l'asthme aigu sévère de l'enfant résiste au traitement de première ligne (SABA, corticoïdes, ipratropium), le choix du traitement de recours manque de comparaisons directes. Cette méta-analyse de RCTs compare tête-à-tête cinq options (aminophylline IV, SABA IV, magnésium IV, kétamine, adrénaline SC) sur l'efficacité et la tolérance — une aide à la décision clinique qui faisait défaut.",
        "impact_pratique": "En pratique : en cas d'asthme sévère réfractaire, le magnésium IV présente le meilleur profil efficacité/tolérance parmi les cinq options comparées — c'est la molécule de deuxième ligne à privilégier.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-11-19"
    }),
    ("70cb6370", {
        "titre_court": "Nourrisson fébrile avec ECBU positif : le risque d'infection invasive est 3,5 fois plus élevé",
        "resume": "La cohorte FIDO (35 urgences pédiatriques au Royaume-Uni et en Irlande, N=1480 nourrissons ≤90 jours) révèle que la bandelette urinaire positive multiplie par 3,5 le risque d'infection bactérienne invasive (IBI) : 7,7% d'IBI en cas de bandelette positive versus 2,2% en cas de bandelette négative. Ce résultat quantifie pour la première fois ce sur-risque dans une cohorte prospective de grande taille.",
        "impact_pratique": "En pratique : devant un nourrisson ≤90 jours fébrile avec bandelette urinaire positive, compléter le bilan par une hémoculture et discuter la ponction lombaire — le risque d'IBI concomitante n'est pas négligeable.",
        "nature": "ETUDE",
        "date_publication": "2025-12-15"
    }),
    ("0c5a556b", {
        "titre_court": "Coqueluche en PICU, 2023-2024 : 20% de mortalité, mères non vaccinées",
        "resume": "L'épidémie britannique de coqueluche 2023-2024 a conduit 54 nourrissons en réanimation pédiatrique nationale. L'audit révèle une mortalité de 20% (11/54), concentrée chez les moins de 3 mois, et un constat frappant : seulement 23% des mères avaient reçu la vaccination coqueluche pendant la grossesse, contre 59% de moyenne nationale. La leuco-réduction extracorporelle d'urgence est apparue comme le facteur pronostique déterminant dans les formes hyperleuco-cytaires.",
        "impact_pratique": "En pratique : la vaccination coqueluche maternelle au 3ème trimestre est le levier préventif principal — une couverture insuffisante entraîne des formes néonatales d'une gravité documentée ici.",
        "nature": "ETUDE",
        "date_publication": "2025-11-19"
    }),
    ("cc7058e6", {
        "titre_court": "Tumeurs abdominales de l'enfant : les signes d'alerte qui raccourcissent le délai diagnostique",
        "resume": "Le délai diagnostique dans les tumeurs abdominales pédiatriques reste une cible prioritaire d'amélioration. Cette revue systématique et méta-analyse (MEDLINE/Embase, 2005-2023) identifie les signes cliniques pré-diagnostiques les plus discriminants — masse palpable, douleur abdominale persistante, hématurie — pour guider les cliniciens de première ligne vers une imagerie rapide.",
        "impact_pratique": "En pratique : toute masse abdominale palpable, douleur abdominale persistante ou hématurie chez l'enfant justifie une imagerie dans les 48 heures — ne pas attendre une consultation spécialisée pour initier le bilan.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-01-19"
    }),
    ("547acd56", {
        "titre_court": "Hypertension artérielle pédiatrique en Europe : plus fréquente qu'on ne le croit",
        "resume": "La prévalence de l'hypertension artérielle pédiatrique en Europe reste mal connue, les études étant hétérogènes dans leurs seuils et leurs populations. Cette méta-analyse d'études populationnelles (1990-présent) révèle une prévalence variant de 1 à 20% selon les critères, avec une tendance à la hausse parallèle à l'épidémie d'obésité. La HTA pédiatrique est probablement sous-diagnostiquée dans les consultations de suivi courantes.",
        "impact_pratique": "En pratique : mesurer la tension artérielle à chaque consultation de suivi dès l'âge de 3 ans — la HTA pédiatrique est fréquente, sous-détectée, et ses conséquences cardiovasculaires à long terme commencent dans l'enfance.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-19"
    }),
    ("deaa3bab", {
        "titre_court": "Insuline glargine précoce dans l'acidocétose pédiatrique : un essai randomisé en double aveugle",
        "resume": "Le moment optimal pour introduire l'insuline basale dans la prise en charge de l'acidocétose diabétique pédiatrique reste débattu. Cet essai randomisé en double aveugle (PICU tertiaire, Inde, juillet 2022-juin 2023) évalue le bénéfice d'un démarrage précoce de la glargine en overlap (≥4h) avec l'insuline IV sur le délai de résolution de l'acidocétose, sans augmenter le risque hypoglycémique.",
        "impact_pratique": "En pratique : l'introduction précoce de l'insuline glargine pendant la phase IV de l'acidocétose est une stratégie à évaluer dans votre protocole institutionnel — les données de cet essai, en parallèle avec la méta-analyse EJP concomitante, permettront de statuer.",
        "nature": "ETUDE",
        "date_publication": "2025-11-19"
    }),
    # ── EUR J PEDIATR ─────────────────────────────────────────────────────────
    ("7d897058", {
        "titre_court": "Infections ostéo-articulaires pédiatriques : le relais oral précoce est sûr",
        "resume": "La durée optimale du traitement intraveineux dans les infections ostéo-articulaires de l'enfant suscite depuis longtemps des pratiques hétérogènes. Cette méta-analyse de 24 études (N=7881) apporte une réponse claire : le passage précoce à l'antibiothérapie orale ne génère pas plus de complications que la voie IV prolongée (RR=0,82 ; IC95% 0,62-1,08 ; p=0,2). Le paradigme du long cours IV n'est plus défendable.",
        "impact_pratique": "En pratique : dès la stabilisation clinique d'une infection ostéo-articulaire pédiatrique non compliquée, initier le relais oral — 7881 patients ne montrent pas de différence de complications.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-03-30"
    }),
    ("3a5d9a95", {
        "titre_court": "Otite moyenne aiguë : 5 jours d'antibiotiques suffisent chez l'enfant de plus de 2 ans",
        "resume": "L'otite moyenne aiguë est la première cause de prescription antibiotique chez l'enfant, et la durée du traitement varie selon les pays et les praticiens. Cette revue systématique (MEDLINE/Embase/CENTRAL jusqu'en février 2024) démontre la non-infériorité des traitements courts (5 jours) par rapport aux traitements longs (8-10 jours) pour l'efficacité clinique — avec l'avantage supplémentaire d'une moindre pression de sélection antibiotique.",
        "impact_pratique": "En pratique : prescrire 5 jours d'amoxicilline dans l'OMA non compliquée de l'enfant de plus de 2 ans — la durée courte est équivalente sur le plan clinique et préférable sur le plan écologique.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-28"
    }),
    ("17d51938", {
        "titre_court": "Angine et diagnostic moléculaire rapide du SGA : moins d'antibiotiques prescrits",
        "resume": "La distinction entre angine virale et angine bactérienne à SGA en consultation libérale reste imprécise avec les seuls tests de diagnostic rapide classiques. Cet essai cluster randomisé en cross-over (25 cabinets pédiatriques, Berlin, décembre 2023-mai 2024) montre que l'ajout d'un test moléculaire point-of-care améliore le ciblage des antibiotiques et réduit les prescriptions inappropriées dans les angines pédiatriques.",
        "impact_pratique": "En pratique : le test moléculaire rapide SGA, plus sensible et spécifique que le TDR classique, permet de guider les prescriptions antibiotiques dans les angines pédiatriques en consultation courante.",
        "nature": "ETUDE",
        "date_publication": "2026-03-10"
    }),
    ("0ea38443", {
        "titre_court": "Pneumonie réfractaire à Mycoplasma pneumoniae : prévalence et facteurs prédictifs dans 53 études",
        "resume": "La résistance aux macrolides de Mycoplasma pneumoniae et la recrudescence des infections post-COVID rendent la pneumonie réfractaire (rMPP) plus difficile à reconnaître et à traiter. Cette méta-analyse de 53 études (N=35 275 enfants) établit la prévalence globale de la rMPP, identifie les facteurs de risque cliniques (âge scolaire, infiltrat lobaire, résistance aux macrolides) et évalue la précision des modèles prédictifs disponibles.",
        "impact_pratique": "En pratique : devant une pneumonie à M. pneumoniae qui ne s'améliore pas sous macrolide après 7 jours, évoquer activement la rMPP et passer à la doxycycline (>8 ans) ou à une quinolone selon le terrain.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-02-21"
    }),
    ("3aa303b5", {
        "titre_court": "Acidocétose diabétique pédiatrique : l'insuline basale précoce réduit-elle la durée ?",
        "resume": "Introduire l'insuline basale (glargine ou détémir) pendant la phase intraveineuse de l'acidocétose diabétique pédiatrique, avec un chevauchement d'au moins 4 heures, pourrait accélérer la résolution de l'acidose et simplifier la transition. Cette méta-analyse GRADE (PROSPERO CRD420251155626) synthétise les données disponibles sur la durée de résolution, le temps sous insuline IV, la durée d'hospitalisation et le risque hypoglycémique.",
        "impact_pratique": "En pratique : le chevauchement précoce insuline basale/insuline IV est une stratégie prometteuse dans l'acidocétose pédiatrique — les résultats de cette méta-analyse GRADE permettront de statuer sur son intégration dans les protocoles.",
        "nature": "META-ANALYSE",
        "date_publication": "2025-11-26"
    }),
    ("f758956d", {
        "titre_court": "COVID Omicron et convulsions fébriles : un risque majoré confirmé par 36 études",
        "resume": "Les observations cliniques suggèrent depuis 2022 que le variant Omicron de SARS-CoV-2 est associé à une incidence accrue de convulsions fébriles chez l'enfant. Cette méta-analyse de 36 études (N=82 591 enfants avec COVID confirmé, dont 2051 convulsions) le confirme : l'incidence de convulsions fébriles est significativement plus élevée en période Omicron qu'en période pré-Omicron, en particulier chez les enfants hospitalisés.",
        "impact_pratique": "En pratique : informer les parents d'enfants en âge de convulsion fébrile (6 mois-5 ans) que le COVID-Omicron augmente ce risque — recommander une surveillance accrue de la fièvre et rappeler la conduite à tenir.",
        "nature": "META-ANALYSE",
        "date_publication": "2026-01-31"
    }),
    ("5aba2e24", {
        "titre_court": "Fond d'œil avant ponction lombaire : une limite que 3 cas rappellent",
        "resume": "La fondoscopie est souvent réalisée avant ponction lombaire (PL) pour exclure une hypertension intracrânienne dans les méningites pédiatriques. Dans cette cohorte de 1742 enfants (15 urgences pédiatriques, 2018-2023), le papilloedème était rare (2,8%) et tous ont bénéficié d'une PL sans complication. Mais trois enfants avec fond d'œil normal présentaient une lésion intracrânienne au scanner (deux abcès, une tumeur), confirmant que la fondoscopie ne suffit pas à exclure une contre-indication.",
        "impact_pratique": "En pratique : un fond d'œil normal ne dispense pas du scanner en présence de signes focaux ou d'ACSOS — la PL peut être différée sans perdre en urgence diagnostique.",
        "nature": "ETUDE",
        "date_publication": "2025-11-14"
    }),
    ("3ff1711d", {
        "titre_court": "RSV sévère après 1 an : les facteurs de risque dans l'ère du nirsévimab",
        "resume": "L'expansion de la prophylaxie RSV longue durée (nirsévimab) soulève la question de la protection dans la deuxième année de vie. Cette étude multicentrique rétrospective (11 centres, 2017-2021, N=enfants 12-23 mois hospitalisés pour RSV) identifie les facteurs associés à une hospitalisation prolongée (>3 jours) ou à une admission en PICU : prématurité <37 SA, cardiopathie congénitale, dysplasie bronchopulmonaire et trisomie 21.",
        "impact_pratique": "En pratique : identifier dès la première saison les enfants 12-23 mois avec ces facteurs de risque pour anticiper une prophylaxie lors de la deuxième saison RSV si les données d'efficacité du nirsévimab à cet âge le permettent.",
        "nature": "ETUDE",
        "date_publication": "2025-11-27"
    }),
    ("0eb64262", {
        "titre_court": "Rougeole 2023 en Turquie : enfants non vaccinés, complications graves, signal d'alerte européen",
        "resume": "La rougeole connaît un regain mondial depuis 2022, avec un pic en 2024. Cette cohorte rétrospective (34 centres turcs, 2023) de tous les enfants ≤18 ans hospitalisés avec rougeole WHO-confirmée documente le profil de sévérité, les complications (pulmonaires, neurologiques) et l'impact du statut vaccinal. Dans un contexte d'érosion de la couverture vaccinale en Europe, ce signal clinique est directement pertinent.",
        "impact_pratique": "En pratique : vérifier le statut vaccinal ROR à chaque consultation et rappeler les enfants incompletement vaccinés — devant tout enfant fébrile avec éruption et non vacciné, évoquer la rougeole et isoler avant confirmation.",
        "nature": "ETUDE",
        "date_publication": "2025-10-29"
    }),
    ("eaedc4b5", {
        "titre_court": "Mycoplasma pneumoniae post-COVID : résurgence, formes extrapulmonaires et résistances",
        "resume": "Après la levée des mesures barrières, M. pneumoniae a resurgi globalement avec des phénotypes cliniques qui semblent différents de la période pré-COVID. Cette cohorte multicentrique turque (20 centres tertiaires, N=400 enfants hospitalisés, 2021-2024) caractérise la gravité, les manifestations extrapulmonaires (neurologiques, cardiaques, cutanées) et identifie les facteurs de risque de forme critique, dont la résistance aux macrolides.",
        "impact_pratique": "En pratique : en cas de pneumonie à M. pneumoniae avec signes extrapulmonaires ou absence de réponse au macrolide, anticiper l'escalade thérapeutique — cette cohorte fournit les critères de risque pour décider précocement.",
        "nature": "ETUDE",
        "date_publication": "2025-11-20"
    }),
    ("3a35dae8", {
        "titre_court": "Sevrage HFNC dans la bronchiolite sévère : l'infirmière peut décider",
        "resume": "Dans la bronchiolite sévère nécessitant une oxygénothérapie haut débit, le moment du sevrage reste souvent laissé à l'appréciation médicale, source de variabilité. Cet essai randomisé contrôlé dans deux PICU tertiaires teste un protocole de sevrage infirmier structuré — combinant le score de Wang (WBSS) et l'index ROX — et mesure son impact sur la durée totale de HFNC.",
        "impact_pratique": "En pratique : un protocole de sevrage HFNC piloté par les infirmières (WBSS + ROX index) réduit la durée d'oxygénothérapie en bronchiolite sévère et libère du temps médical — à intégrer dans les protocoles de service.",
        "nature": "ETUDE",
        "date_publication": "2026-03-23"
    }),
    ("6e1e0f48", {
        "titre_court": "HFNC en bronchiolite : 1, 2 ou 3 L/kg/min — premier essai comparatif direct",
        "resume": "L'oxygénothérapie haut débit est devenue le traitement de référence de la bronchiolite modérée à sévère du nourrisson, mais le débit optimal n'a jamais été comparé directement. Ce premier essai randomisé (N=90, 30 par groupe, nourrissons 1-12 mois) compare trois débits (1, 2 et 3 L/kg/min) selon les critères AAP 2014 — une question pratique quotidienne enfin investiguée.",
        "impact_pratique": "En pratique : en attendant la confirmation des résultats, initier à 2 L/kg/min et ajuster selon la réponse clinique — cet essai est le premier à confronter directement les trois débits habituellement utilisés.",
        "nature": "ETUDE",
        "date_publication": "2025-12-23"
    }),
]

print(f"Corrections à appliquer : {len(CORRECTIONS)}")
updated = 0
errors = []

for prefix, new_tj in CORRECTIONS:
    cur.execute(
        """UPDATE items SET tri_json=%s
           WHERE candidate_id::text LIKE %s AND specialty_slug='pediatrie'""",
        (json.dumps(new_tj, ensure_ascii=False), prefix + "%")
    )
    if cur.rowcount == 1:
        updated += 1
        print(f"  OK : {prefix} — {new_tj['titre_court'][:60]}")
    else:
        errors.append(prefix)
        print(f"  ERREUR (rowcount={cur.rowcount}) : {prefix}")

conn.commit()
print(f"\n=== Résultat ===")
print(f"Mis à jour : {updated}")
print(f"Erreurs    : {len(errors)}")
if errors:
    for e in errors:
        print(f"  {e}")
conn.close()
