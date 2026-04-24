#!/usr/bin/env python3
"""
Correction du ton rédactionnel — chirurgie-pédiatrique (157 items)
Style cible : Journal of Pediatric Surgery, European Journal of Pediatric Surgery
"""
import psycopg2, json

DB = 'postgresql://neondb_owner:npg_sE8HTY1MrQCZ@ep-quiet-cell-al32rblz-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'

# (candidate_id_prefix, new_titre_court, new_resume, new_impact_pratique)
# None = garder l'existant
UPDATES = [
    # SCORE 9
    ("1d5acdf0",
     "Anomalies vasculaires pédiatriques — 1ères recommandations japonaises GRADE, 38 questions cliniques",
     "Première synthèse japonaise de niveau GRADE sur la prise en charge des anomalies vasculaires pédiatriques (hémangiomes, MAV, malformations veineuses, lymphatiques, lymphangiomatose). Trente-huit questions cliniques abordent les indications respectives de la chirurgie, de la sclérothérapie, de l'embolisation, du propranolol, du sirolimus et du laser selon le type et la localisation de la lésion.",
     "En pratique : référentiel GRADE applicable immédiatement en staff multidisciplinaire pour les anomalies vasculaires pédiatriques — premier document japonais avec niveau de preuve explicite pour chaque décision thérapeutique."),

    # SCORE 8
    ("0dcace4f",
     "Maladie de Hirschsprung : opérer entre 3 et 12 mois optimise les résultats fonctionnels",
     "Selon cette méta-analyse, la chirurgie définitive réalisée entre 3 et 12 mois est associée aux meilleurs résultats fonctionnels à court et long terme dans la maladie de Hirschsprung. Les interventions après 12 mois exposent à une dégradation significative des outcomes, consolidant l'argument pour une prise en charge chirurgicale précoce.",
     "En pratique : planifier la chirurgie définitive de Hirschsprung avant 12 mois — ce délai n'est pas neutre sur la continence et la qualité de vie à long terme."),

    ("4ceb7568",
     "Prophylaxie antibiotique continue dans le RVU : méta-analyse actualisée des ECR",
     "Cette méta-analyse actualisée précise les bénéfices de la prophylaxie antibiotique continue (PAC) sur la prévention des infections urinaires fébriles dans le reflux vésico-urétéral pédiatrique. L'analyse en sous-groupes réidentifie les profils — grade de RVU, sexe, antécédents d'IU — pour lesquels le rapport bénéfice/risque de la PAC justifie une prescription ciblée.",
     "En pratique : la PAC n'est pas universelle dans le RVU — cette méta-analyse précise les critères de sélection pour une prophylaxie justifiée, notamment dans les RVU de haut grade."),

    ("5a37a23c",
     "Appendicite non compliquée pédiatrique : antibiothérapie — taux d'échec et critères de sélection redéfinis",
     "Cette méta-analyse actualisée des ECR documente le taux d'échec à court terme (appendicectomie dans les 30 jours) et à long terme (récidive sur 1-5 ans) du traitement non opératoire de l'appendicite non compliquée pédiatrique, et identifie les critères anatomiques et cliniques associés à un plus fort risque d'échec.",
     "En pratique : le traitement antibiotique seul reste une option valide pour l'appendicite non compliquée pédiatrique bien sélectionnée — les critères de contre-indication et d'échec précoce issus de cette méta-analyse doivent guider la discussion avec la famille."),

    ("8b249046",
     "RVU primitif pédiatrique : classement comparatif de tous les traitements par méta-analyse en réseau",
     "Cette méta-analyse en réseau positionne tous les traitements du reflux vésico-urétéral primitif pédiatrique sur une même échelle comparative : surveillance, prophylaxie antibiotique, STING endoscopique et réimplantation urétérale. Le classement intègre l'efficacité sur la résolution du RVU, la prévention des IU et le profil de complications, fournissant une base rationnelle pour personnaliser la décision thérapeutique.",
     "En pratique : la méta-analyse en réseau RVU pédiatrique est la référence pour personnaliser la stratégie thérapeutique — à intégrer dans les RCP de service pour standardiser les indications de STING versus réimplantation."),

    ("9819a0c0",
     "Atrésie de l'œsophage à long écart : algorithme de choix technique validé par méta-analyse",
     "Cette revue systématique compare de façon exhaustive les techniques pour l'atrésie de l'œsophage à long écart (élongation, procédure de Foker, anastomose différée, interposition colique ou gastrique). L'analyse des complications à court terme et des résultats fonctionnels à long terme permet de hiérarchiser les indications selon la longueur du défect et le contexte clinique.",
     "À retenir : aucune technique n'est universellement supérieure dans l'atrésie de l'œsophage à long écart — cette méta-analyse est la référence pour la décision en RCP de centre de compétence."),

    ("b43771c8",
     "Trachéopexie postérieure primaire dans l'atrésie de l'œsophage avec trachéomalacie sévère",
     "Dans les atrésies de l'œsophage compliquées d'une trachéomalacie sévère, cette étude multicentrique documente les résultats fonctionnels de la trachéopexie postérieure réalisée lors de la cure initiale. Les données constituent la base d'un essai randomisé en cours comparant la trachéopexie primaire à la trachéopexie secondaire différée.",
     "En pratique : discuter la trachéopexie postérieure primaire en RCP pour les patients avec trachéomalacie sévère confirmée — évite la réintervention secondaire dans les cas sélectionnés."),

    ("fa032cca",
     "CPAM asymptomatique chez l'enfant : la surveillance non opératoire est sûre",
     "Cette méta-analyse documente la sécurité de la surveillance non opératoire des malformations pulmonaires congénitales asymptomatiques en quantifiant le risque d'infection intercurrente, de transformation maligne et de nécessité de chirurgie secondaire dans les séries de surveillance. Les données confortent l'attitude conservatrice comme stratégie de référence pour les CPAM asymptomatiques sans critère de risque.",
     "En pratique : la surveillance non opératoire est légitime pour les CPAM asymptomatiques — cette méta-analyse précise les seuils cliniques qui doivent faire reconsidérer l'indication chirurgicale."),

    # SCORE 7
    ("06364d5b",
     "Kyste cholédoque pédiatrique : l'hépatico-jéjunostomie présente moins de complications tardives que la hépatico-duodénostomie",
     "Cette première méta-analyse comparant exclusivement la hépatico-duodénostomie (HD) et la hépatico-jéjunostomie (HJ) dans la résection laparoscopique du kyste cholédoque pédiatrique révèle que la HD expose à un risque plus élevé de reflux biliaire et de cholangite tardive. L'HJ est associée à moins de complications biliaires à long terme — argument décisionnel en faveur de l'HJ dans la majorité des cas.",
     "En pratique : préférer l'hépatico-jéjunostomie à la hépatico-duodénostomie pour la reconstruction biliaire après résection de kyste cholédoque pédiatrique — les données méta-analytiques sur les complications tardives sont déterminantes."),

    ("0a267063",
     "Préparation mécanique intestinale préopératoire en chirurgie pédiatrique : bénéfice non démontré en monothérapie",
     "La préparation mécanique intestinale seule n'apporte pas de bénéfice démontré sur la réduction des complications infectieuses et anastomotiques en chirurgie intestinale pédiatrique. Seule la combinaison préparation mécanique et antibiotiques oraux préopératoires montre un signal favorable, alignant les données pédiatriques avec les recommandations ERAS adultes.",
     "En pratique : abandonner la préparation mécanique intestinale isolée avant chirurgie intestinale pédiatrique — seule la combinaison MEP + antibiotiques oraux mérite encore discussion selon le type de chirurgie."),

    ("14fa133e",
     "Gastrostomie pédiatrique : PEG et voie laparoscopique ont des profils de complications distincts",
     "Cette méta-analyse compare la gastrostomie endoscopique percutanée (PEG) et la gastrostomie laparoscopique chez l'enfant. La PEG est associée à davantage de complications péristomales, tandis que la voie laparoscopique offre moins de fuites et une meilleure visualisation — différence particulièrement pertinente chez les enfants avec trouble neurologique ou position gastrique atypique.",
     "En pratique : orienter vers la gastrostomie laparoscopique chez l'enfant avec anatomie difficile ou neurologie complexe — cette méta-analyse documente les sous-groupes pour lesquels la PEG présente un profil de complications moins favorable."),

    ("18be49c9",
     "Orchidopexie laparoscopique en flanc avec médialisation colique : efficacité confirmée pour le testicule intra-abdominal",
     "Cet ECR démontre que l'orchidopexie laparoscopique en position de flanc avec médialisation colique est équivalente à la voie laparoscopique conventionnelle pour le testicule intra-abdominal, en permettant un gain de longueur vasculaire suffisant pour une position scrotale sans tension. Taux de succès anatomique et préservation vasculaire sont comparables entre les deux approches.",
     "En pratique : la technique de flanc avec médialisation colique est une alternative efficace pour l'orchidopexie du testicule intra-abdominal — à maîtriser dans les centres spécialisés en urologie pédiatrique."),

    ("18f4ebf5",
     "IPAA laparoscopique chez l'enfant : morbidité comparable à la voie ouverte, avantages mini-invasifs maintenus",
     "Cette méta-analyse sur la proctocolectomie restauratrice laparoscopique versus ouverte chez l'enfant (RCH, PAF) montre une morbidité globale superposable entre les deux voies. La laparoscopie offre les avantages classiques de la mini-invasivité sans compromis sur les résultats fonctionnels à long terme.",
     "En pratique : l'IPAA laparoscopique est faisable et sûre dans les centres experts — à proposer en première intention pour la RCH et la PAF pédiatriques nécessitant une proctocolectomie restauratrice."),

    ("19358a9c",
     "HTAP dans le CDH : facteurs de risque identifiés pour intensifier la surveillance néonatale",
     "L'hypertension artérielle pulmonaire est le déterminant majeur de la mortalité dans la hernie diaphragmatique congénitale. Cette méta-analyse quantifie son incidence et identifie les facteurs prénataux (hypoplasie pulmonaire sévère, position du foie, rapport poumon/tête) et postnataux associés à son développement.",
     "En pratique : identifier les marqueurs prédictifs d'HTAP dans le CDH dès la période prénatale pour adapter la stratégie péri-opératoire — la présence de facteurs de risque justifie un transfert in utero dans un centre de référence CDH."),

    ("1fc72d22",
     "RGO après atrésie de l'œsophage : complication constante (40-70 %), surveillance endoscopique spécialisée indispensable",
     "Le reflux gastro-œsophagien survient chez 40 à 70 % des patients opérés d'atrésie de l'œsophage selon les séries. Cette méta-analyse en documente l'incidence, les facteurs de risque (grand gap, complications anastomotiques) et les options thérapeutiques, soulignant que ce RGO présente une évolution distincte du RGO commun et nécessite un suivi endoscopique spécialisé prolongé.",
     "En pratique : systématiser la surveillance endoscopique et pH-métrique du RGO chez tous les patients opérés d'atrésie de l'œsophage — les indications de fundoplicature doivent être discutées en centre de référence."),

    ("308f3782",
     "CDH : les patchs biologiques réduisent les récidives par rapport aux synthétiques",
     "Dans la réparation de la hernie diaphragmatique congénitale avec large défect, le patch biologique offre un taux de récidive intermédiaire entre les patchs synthétiques (plus solides mais taux de récidive élevé à 5 ans) et les lambeaux musculaires autologues (meilleure intégration), avec une meilleure tolérance tissulaire.",
     "En pratique : en cas d'impossibilité de réaliser un lambeau musculaire dans le CDH, préférer le patch biologique au synthétique — taux de récidive plus faible et meilleure intégration tissulaire à long terme."),

    ("356a8ecb",
     "Empyème pédiatrique : la fibrinolyse intrapleurale est aussi efficace que la chirurgie en stade II",
     "Cette revue systématique des ECR sur les épanchements parapneumoniques compliqués et empyèmes pédiatriques confirme que la fibrinolyse intrapleurale est équivalente à la VATS pour les empyèmes de stade II, avec la chirurgie réservée aux échecs de fibrinolyse ou aux empyèmes organisés de stade III tardifs.",
     "En pratique : proposer la fibrinolyse intrapleurale en première intention dans les empyèmes de stade II chez l'enfant — réserver la VATS aux échecs ou aux empyèmes organisés de stade III."),

    ("3d4c2e73",
     "Maladie de Hirschsprung : Soave et Swenson donnent des résultats fonctionnels équivalents",
     "Cette méta-analyse comparant les procédures de Soave et Swenson ne montre pas de différence significative sur les résultats fonctionnels à long terme (continence, épisodes d'entérocolite). Les complications peropératoires et la durée d'hospitalisation sont similaires, validant le choix selon l'expertise du centre.",
     "En pratique : Soave et Swenson sont équivalents sur les outcomes fonctionnels dans la maladie de Hirschsprung — choisir selon l'expertise de l'équipe chirurgicale sans compromettre les résultats."),

    ("452693a8",
     "Hernie inguinale du prématuré : la chirurgie différée après sortie de NICU réduit les complications respiratoires",
     "Cette méta-analyse actualisée précise que le risque d'incarcération à court terme est limité et que la réparation différée après la sortie de NICU est associée à moins de complications respiratoires post-opératoires, consolidant la stratégie attentiste dans la majorité des prématurés stables.",
     "En pratique : différer la cure de hernie inguinale chez le prématuré jusqu'après la sortie de NICU — sauf hernie symptomatique ou incarcérée, le risque opératoire précoce l'emporte sur le risque d'incarcération."),

    ("4878e172",
     "Abcès périanal du nourrisson : le traitement non opératoire est efficace en première intention",
     "Cette revue systématique de l'APSA conclut que le traitement non opératoire (antibiotiques, bains de siège) est efficace en première intention pour les abcès périanaux simples du nourrisson. La fistule anale associée évolue souvent favorablement sans chirurgie, ne nécessitant une fistulotomie que dans les récidives ou formes complexes.",
     "En pratique : traiter l'abcès périanal du nourrisson sans chirurgie en première intention — la fistulotomie est à réserver aux récidives ou formes complexes après 6-12 mois de suivi."),

    ("48ce5601",
     "Pectus excavatum — cryoanalgésie associée à un bloc régional : meilleure analgésie post-Nuss",
     "Cette méta-analyse démontre que l'association cryoanalgésie intercostale et bloc anesthésique régional (paravertébral ou érecteur du rachis) améliore significativement l'analgésie dans les premières 24 heures après procédure de Nuss par rapport à la cryoanalgésie seule, avec réduction de la consommation opioïde et mobilisation plus précoce.",
     "En pratique : combiner cryoanalgésie intercostale et bloc anesthésique régional pour la procédure de Nuss — l'association offre une couverture analgésique supérieure à la cryoanalgésie seule dans la phase postopératoire précoce."),

    ("4aa894b0",
     "Invagination iléocæcale : un délai de 6-8 heures avant réduction n'aggrave pas le pronostic",
     "Cette analyse multicentrique confirme que le délai de 6 à 8 heures entre le diagnostic échographique et la réduction non opératoire de l'invagination iléocæcale ne compromet pas le taux de succès ni la morbidité post-procédure. Ces données légitiment une organisation de soin pragmatique, sans urgence nocturne systématique.",
     "En pratique : un délai de 6-8h entre diagnostic et tentative de réduction non opératoire est sécuritaire dans l'invagination iléocæcale — données multicentriques pour une organisation de soin pragmatique."),

    ("54527210",
     "Dyskinésie biliaire pédiatrique : cholécystectomie efficace chez les enfants bien sélectionnés",
     "Chez les 3 348 enfants inclus dans cette méta-analyse, l'amélioration symptomatique post-cholécystectomie est documentée dans la majorité des cas. Les résultats sont hétérogènes selon les critères de sélection : les patients avec fraction d'éjection biliaire basse et douleurs reproductibles à la cholescintigraphie présentent les meilleurs outcomes.",
     "En pratique : la cholécystectomie est efficace dans la dyskinésie biliaire pédiatrique bien sélectionnée — fraction d'éjection basse avec symptômes reproductibles à la cholescintigraphie reste le meilleur prédicteur de succès."),

    ("5918b197",
     "Appendicite perforée pédiatrique : 3 à 5 jours d'antibiothérapie post-opératoire sont suffisants",
     "Cette méta-analyse valide l'efficacité des régimes antibiotiques raccourcis (3-5 jours) versus les schémas longs (7-10 jours) en post-opératoire d'appendicite perforée pédiatrique, sans augmentation du taux d'abcès résiduels ni de réhospitalisation. Ces données s'inscrivent dans les stratégies d'antibiotic stewardship en chirurgie pédiatrique.",
     "En pratique : 3-5 jours d'antibiothérapie post-opératoire suffisent dans l'appendicite perforée pédiatrique — raccourcir les durées sans compromis sur l'efficacité, conformément aux principes d'antibiotic stewardship."),

    ("63b12450",
     "Gastroschisis : la fermeture sans suture réduit la durée de ventilation et le délai de reprise alimentaire",
     "Cette méta-analyse démontre que la fermeture gastroschisis sans suture est associée à une réduction significative de la durée de ventilation mécanique et du délai de retour à l'alimentation entérale, lorsque la réintégration viscérale complète est réalisable en salle de travail ou au lit.",
     "En pratique : privilégier la fermeture sans suture dans le gastroschisis simple lorsque la réintégration viscérale est possible — réduction documentée de la morbidité néonatale par rapport à la fermeture suturée classique."),

    ("667fc67c",
     "Tumeur de Wilms : la laparoscopie après chimiothérapie SIOP est oncologiquement sûre",
     "Cette méta-analyse sur la néphrectomie laparoscopique versus ouverte pour tumeur de Wilms après chimiothérapie néoadjuvante SIOP montre des résultats oncologiques comparables (marges, survie sans récidive) en stades I-II, avec les avantages périopératoires de la mini-invasivité.",
     "En pratique : la laparoscopie est oncologiquement sûre pour la tumeur de Wilms après chimiothérapie SIOP en stade I-II dans un centre expert — à discuter en RCP d'oncopédiatrie selon la taille résiduelle et l'accessibilité tumorale."),

    ("783275a4",
     "Pectus excavatum modéré : le vacuum bell est une alternative non chirurgicale valide",
     "La cloche à vide constitue une option non chirurgicale efficace dans le pectus excavatum pédiatrique modéré. Cette méta-analyse quantifie la probabilité de succès selon l'index de Haller initial, l'âge de début et l'observance, identifiant les sous-groupes pour lesquels le résultat est comparable à la procédure de Nuss sans ses risques.",
     "En pratique : proposer le vacuum bell dans les pectus excavatum modérés chez l'enfant avant la puberté — évite la chirurgie dans un sous-groupe sélectionné, à condition d'une observance prolongée (>2 ans)."),

    ("7a532b77",
     "CPT pédiatrique : multifocalité (HR 1,86) et extension extrathyroïdienne (HR 1,78) prédisent la récidive",
     "Dans cette méta-analyse portant sur 2 641 enfants atteints de carcinome papillaire thyroïdien, la multifocalité (HR 1,86) et l'extension extrathyroïdienne (HR 1,78) ressortent comme prédicteurs indépendants de récidive. À l'inverse, les métastases ganglionnaires latérales ne prédisent pas significativement la récidive à distance.",
     "En pratique : surveiller de près les patients thyroïdectomisés pour CPT pédiatrique avec multifocalité ou extension extrathyroïdienne — ces facteurs justifient la discussion systématique d'un traitement adjuvant à l'iode 131."),

    ("7ffaf07e",
     "Traumatisme pancréatique pédiatrique : le traitement conservateur est sûr et efficace en première intention",
     "Cette méta-analyse confirme que le traitement conservateur (drainage percutané, CPRE, surveillance) est sûr et efficace en première intention dans les traumatismes pancréatiques pédiatriques y compris en grade III, la chirurgie étant réservée aux échecs ou aux complications tardives. La mortalité n'est pas augmentée par rapport à la chirurgie d'emblée.",
     "En pratique : traiter le traumatisme pancréatique pédiatrique de manière conservatrice — la chirurgie n'est indiquée qu'en cas d'instabilité hémodynamique ou d'échec de la gestion non opératoire après 72 heures."),

    ("83e58bf5",
     "Cryptorchidie : opérer avant 12-18 mois préserve la spermatogenèse",
     "Cette méta-analyse confirme que l'orchidopexie avant 12 à 18 mois est associée à une meilleure préservation des cellules germinales, de l'inhibine B et des paramètres spermiques à l'âge adulte. L'intervention après 24 mois expose à une dégradation significative du potentiel fertilisant dans la cryptorchidie unilatérale et bilatérale.",
     "En pratique : opérer la cryptorchidie avant 12-18 mois — cette fenêtre thérapeutique est solidement étayée et doit être respectée dans les filières de soins pour préserver le potentiel de fertilité."),

    ("8945dcc9",
     "Chirurgie urologique robot-assistée chez le nourrisson ≤10 kg : faisable et sûre en centre expert",
     "Le registre FRUCT, le plus grand registre international disponible, montre une faisabilité et une sécurité de la chirurgie urologique robotique chez les nourrissons <10 kg comparables aux données pédiatriques de référence, avec un taux de conversion acceptable et une courbe d'apprentissage documentée.",
     "En pratique : la chirurgie urologique robot-assistée est réalisable dès les premiers mois de vie dans un centre expert — la courbe d'apprentissage est documentée, les critères de sélection précisés."),

    ("90139dae",
     "Microstomies post-caustiques : l'algorithme multimodal double l'ouverture buccale (ICD 17 → 34 mm)",
     "Cette revue systématique et série de cas (n=30 patients, âge moyen 9,4 ans) valide un protocole multimodal standardisé (libération, lambeau muqueux, greffe cutanée, appareillage dynamique) pour les microstomies post-caustiques pédiatriques, avec une intercision canine passant de 17,3 à 34,0 mm en moyenne après traitement complet.",
     "En pratique : appliquer la séquence libération–lambeau–appareillage dynamique dès stabilisation cicatricielle — algorithme applicable dès 1 an avec gain fonctionnel documenté sur la déglutition et la parole."),

    ("91e5ea68",
     "Cancer thyroïdien différencié pédiatrique à bas risque : la lobectomie est une option valide",
     "Cette méta-analyse remet en question l'indication systématique de la thyroïdectomie totale dans le cancer thyroïdien différencié pédiatrique à faible risque. Pour les tumeurs T1-T2 N0 M0, la lobectomie offre une survie sans récidive comparable avec un profil de complications (hypoparathyroïdie, paralysie récurrentielle) significativement plus favorable.",
     "En pratique : la lobectomie est oncologiquement équivalente à la thyroïdectomie totale pour le CPT pédiatrique à faible risque — à discuter en RCP d'oncopédiatrie pour éviter les complications de la totalisation inutile."),

    ("9da2338c",
     "Voiturettes électriques au bloc opératoire : réduction efficace de l'anxiété préopératoire chez l'enfant",
     "Cet ECR en grappes démontre que le transport en voiturette électrique réduit significativement l'anxiété préopératoire évaluée par l'échelle mYPAS par rapport au transport conventionnel. L'effet est indépendant de l'âge et ne nécessite pas de prémédication supplémentaire.",
     "En pratique : les voiturettes électriques réduisent l'anxiété préopératoire — mesure comportementale simple, peu coûteuse, applicable dans tout service de chirurgie pédiatrique ambulatoire."),

    ("a2b48e6d",
     "Atrésie de l'œsophage : préserver la veine azygos réduit les complications anastomotiques",
     "Cette méta-analyse (JPS) compare la ligature versus la préservation de la veine azygos lors de la cure d'atrésie de l'œsophage. La préservation est associée à un risque plus faible de déhiscence anastomotique et de sténose en maintenant une vascularisation collatérale favorable à la cicatrisation.",
     "En pratique : préserver la veine azygos lors de la cure d'atrésie de l'œsophage chaque fois que la technique le permet — bénéfice sur les complications anastomotiques documenté par méta-analyse."),

    ("a4b25d9e",
     "NEC néonatale : la réalimentation entérale précoce (48-72h post-op) est sûre et raccourcit la nutrition parentérale",
     "Cette méta-analyse synthétise les preuves sur le timing de la réalimentation entérale après chirurgie de NEC. Une réintroduction dans les 48-72 heures post-opératoires est faisable et sûre, associée à une durée de nutrition parentérale plus courte et un meilleur développement de la flore, sans augmentation du risque de récidive ou de complications anastomotiques.",
     "En pratique : débuter l'alimentation entérale dans les 48-72 heures post-opératoires après chirurgie de NEC — la nutrition parentérale prolongée n'est pas bénéfique au-delà de cette fenêtre."),

    ("aae07220",
     "Hypospadias distal : le PRP autologue en couverture urétrale réduit le taux de fistule (technique Snodgrass)",
     "Cet ECR démontre que l'ajout d'une couverture autologue en plasma riche en plaquettes dans la technique Snodgrass pour hypospadias distal réduit significativement le taux de fistule urétrocutanée post-opératoire, par libération locale de facteurs de croissance favorisant la cicatrisation.",
     "En pratique : envisager le PRP autologue comme couverture urétrale complémentaire dans la réparation d'hypospadias distal — l'ECR montre une réduction du taux de fistule sans complication supplémentaire."),

    ("b56a8ad7",
     "Post-Kasai : la bilirubine à J30 (<20 µmol/L) prédit la survie du foie natif",
     "Cette méta-analyse identifie la bilirubine totale, la GGT et l'albumine à 1-3 mois post-Kasai comme prédicteurs indépendants de la survie du foie natif à 2 ans. Une bilirubine totale <20 µmol/L à J30 constitue le seuil prédictif le plus robuste, justifiant son intégration dans les protocoles de surveillance post-opératoire.",
     "En pratique : utiliser la bilirubine totale à J30 post-Kasai comme principal marqueur pronostique — une valeur <20 µmol/L identifie les patients susceptibles d'éviter la transplantation à court terme."),

    ("b954a588",
     "Appendicite perforée pédiatrique : pip/tazo et ceftriaxone/métronidazole sont interchangeables",
     "Cette méta-analyse ne montre pas de différence significative entre la pipéracilline/tazobactam et la combinaison ceftriaxone/métronidazole en termes d'abcès résiduel, réhospitalisation et durée d'hospitalisation dans l'antibiothérapie post-opératoire de l'appendicite perforée pédiatrique.",
     "En pratique : pip/tazo et ceftriaxone/métronidazole sont interchangeables dans l'appendicite perforée pédiatrique — orienter le choix selon l'écologie locale et les résistances documentées dans le service."),

    ("bffbee13",
     "Préservation de la veine azygos dans l'atrésie œsophagienne : bénéfice confirmé par le groupe PESMA",
     "Le groupe PESMA confirme que la préservation systématique de la veine azygos lors de la cure d'atrésie de l'œsophage réduit les complications anastomotiques (sténose, déhiscence). Ces données, combinées à la méta-analyse JPS, constituent un corpus probant pour modifier la technique de référence.",
     "En pratique : la préservation de la veine azygos lors de la cure d'EA-TEF doit devenir le standard technique — deux méta-analyses (JPS et PESMA) convergent vers ce bénéfice."),

    ("cac811aa",
     "Obstruction duodénale congénitale : la correction laparoscopique est réalisable avec des résultats comparables",
     "Cette étude rétrospective multicentrique coréenne confirme la faisabilité de la correction laparoscopique (duodénoduodénostomie en diamant), avec des résultats périopératoires comparables à la voie ouverte en termes de reprise alimentaire et de durée d'hospitalisation. La durée opératoire est plus longue, reflétant la courbe d'apprentissage.",
     "En pratique : la correction laparoscopique de l'obstruction duodénale congénitale est une option valide dans les centres pédiatriques expérimentés — avantages cosmétiques et cicatriciels sans compromettre les résultats fonctionnels."),

    ("cea5bc8c",
     "RVU pédiatrique : réimplantation urétérale robotique équivalente à la chirurgie ouverte",
     "Cette méta-analyse compare la réimplantation urétérale robotique et ouverte chez l'enfant. Les taux de succès sont équivalents, avec une durée d'hospitalisation et une douleur post-opératoire plus favorables en robotique. La technique requiert une courbe d'apprentissage documentée dans les centres à haut volume.",
     "En pratique : la réimplantation robotique est une alternative valide à la chirurgie ouverte dans les centres équipés — résultats fonctionnels comparables avec les avantages de la mini-invasivité."),

    ("d2ba8a3b",
     "Hypospadias distal : la technique TIP préserve les résultats uroflowmétriques à long terme",
     "Cette méta-analyse sur les résultats mictionnels après cure d'hypospadias distal par technique TIP montre que le débit urinaire maximal et les paramètres uroflowmétriques sont comparables aux techniques alternatives, confortant le TIP comme standard chirurgical sans compromettre la fonction mictionnelle.",
     "En pratique : la technique TIP maintient des résultats uroflowmétriques normaux dans l'hypospadias distal — réaliser une uroflowmétrie de contrôle à 2-3 ans pour dépister les sténoses méatiques silencieuses."),

    ("d488b107",
     "Pseudokystes pancréatiques pédiatriques : le drainage endoscopique est l'option de première ligne",
     "Cette méta-analyse positionne le drainage endoscopique (kysto-gastrostomie ou kysto-duodénostomie) comme traitement de première intention devant le drainage percutané et la chirurgie, avec un taux de résolution plus élevé et une moindre morbidité. La surveillance seule reste valide pour les pseudokystes asymptomatiques sans progression.",
     "En pratique : opter pour le drainage endoscopique en première ligne dans les pseudokystes pancréatiques pédiatriques symptomatiques — le drainage percutané ou chirurgical est à réserver aux échecs ou aux anatomies non accessibles par voie endoscopique."),

    ("dfb5ab1a",
     "Sphérocytose héréditaire pédiatrique : la splénectomie partielle préserve la fonction immunitaire sans compromettre l'efficacité",
     "Cette étude prospective comparative montre que la splénectomie partielle préserve la fonction immunologique splénique et réduit le risque infectieux post-opératoire à long terme sans compromettre le contrôle de l'hémolyse et l'amélioration de l'anémie. La récidive de l'hypersplénisme survient dans moins de 10 % des cas à 5 ans.",
     "En pratique : privilégier la splénectomie partielle dans la sphérocytose héréditaire pédiatrique — les données à long terme confirment la préservation splénique sans compromettre le bénéfice hématologique."),

    ("e54402e8",
     "Cryptorchidie : hormonothérapie préopératoire + orchidopexie améliore le potentiel de fertilité",
     "Cette méta-analyse confirme que le traitement combiné (LH-RH ou HCG préopératoire + orchidopexie) est associé à une meilleure préservation du capital spermatogénique et de meilleurs paramètres spermiques à l'âge adulte par rapport à l'orchidopexie seule.",
     "En pratique : associer une hormonothérapie préopératoire à l'orchidopexie dans la cryptorchidie bilatérale ou chez les patients à risque de fertilité compromise — bénéfice sur la spermatogenèse documenté."),

    ("e88575f7",
     "Atrésie de l'œsophage et très faible poids de naissance : mortalité élevée, stratégie chirurgicale à adapter",
     "Cette étude de cohorte multicentrique sur les prématurés VLBW/ELBW opérés d'atrésie de l'œsophage documente une morbidité et mortalité significativement plus élevées qu'à terme. Le poids de naissance, le statut respiratoire préopératoire et les malformations associées sont les principaux déterminants du pronostic.",
     "En pratique : dans l'atrésie de l'œsophage avec poids <1 500g, discuter systématiquement une stratégie en deux temps (gastrostomie + ligature de fistule) avant la cure définitive — la décision doit être collégiale avec l'équipe néonatale."),

    ("e93602d3",
     "Anneau gastrique chez l'adolescent obèse sévère : perte de poids maintenue à 8 ans mais taux de réintervention élevé",
     "Cet ECR de 8 ans montre une perte de poids modérée mais maintenue avec le LAGB versus traitement conservateur chez les adolescents obèses sévères. Le taux de réintervention (ablation, révision) est significatif, soulevant des questions sur la place du LAGB face à des procédures plus efficaces.",
     "En pratique : le LAGB adolescent offre une perte de poids durable mais avec un taux de réintervention important — à réserver aux patients non éligibles à la sleeve ou au bypass après discussion multidisciplinaire."),

    ("e952ce2d",
     "Hépatoblastome R1 avec chimiothérapie complète : survie comparable à R0, ré-résection non systématique",
     "Cette méta-analyse nuance l'impact pronostique des marges R1 dans l'hépatoblastome pédiatrique. En présence d'une chimiothérapie adjuvante complète et d'une AFP normalisée, la survie sans récidive des patients R1 n'est pas significativement différente des marges R0.",
     "En pratique : une marge R1 focale dans l'hépatoblastome ne justifie pas nécessairement une ré-résection si la chimiothérapie est complète et l'AFP normalisée — à discuter en RCP d'oncopédiatrie au cas par cas."),

    ("ec060a03",
     "CDH : les patchs biologiques ont moins de complications infectieuses que les synthétiques",
     "Cette méta-analyse montre que les patchs biologiques présentent une meilleure tolérance tissulaire et moins de complications infectieuses que les patchs synthétiques dans la réparation du CDH, avec un taux de récidive intermédiaire entre les synthétiques (élevé) et les lambeaux musculaires.",
     "En pratique : dans la réparation du CDH avec large défect sans possibilité de lambeau musculaire, préférer le patch biologique au synthétique — meilleure tolérance tissulaire et moins de complications infectieuses."),

    ("ecf68569",
     "Torsion ovarienne primitive pédiatrique : l'oophoropexie bilatérale réduit le risque de récidive",
     "Cette méta-analyse montre une réduction significative du risque de récidive ipsi et controlatérale après oophoropexie lors de la prise en charge d'une torsion ovarienne primitive. Le taux de récidive sans fixation atteint 10-15 % dans certaines séries.",
     "En pratique : réaliser une oophoropexie bilatérale lors de la prise en charge d'une torsion ovarienne primitive pédiatrique — risque de récidive sans fixation justifie la fixation systématique, notamment chez les jeunes filles prépubères."),

    ("f1437e46",
     "Pyéloplastie robot-assistée chez le nourrisson ≤12 mois : faisable avec des résultats comparables à la voie ouverte",
     "Cette étude multicentrique démontre que la pyéloplastie robot-assistée chez les nourrissons <12 mois présente un taux de succès anatomique et fonctionnel comparable à la chirurgie ouverte. La durée opératoire est plus longue, reflet de la courbe d'apprentissage dans cette tranche d'âge.",
     "En pratique : la pyéloplastie robot-assistée est une option valide pour les jonctions pyélo-urétérales du nourrisson dans les centres spécialisés — résultats à 2 ans comparables à la pyéloplastie ouverte de référence."),

    ("f7aa2cf0",
     "Pancréatite lithiasique pédiatrique avec obstruction biliaire : la CPRE précoce (48-72h) réduit les complications",
     "Cette étude du consortium WPRC montre que la CPRE précoce dans les 48-72 heures est associée à une résolution plus rapide de l'ictère obstructif et une durée d'hospitalisation plus courte dans la pancréatite lithiasique pédiatrique avec obstruction biliaire persistante.",
     "En pratique : envisager la CPRE dans les 48-72 heures en cas de pancréatite lithiasique pédiatrique avec obstruction biliaire persistante — les données WPRC confortent l'indication précoce dans les centres équipés."),

    ("fd05072d",
     "Hernie inguinale pédiatrique : l'essai PIHRL confirme la supériorité de la laparoscopie pour la détection des hernies controlatérales",
     "L'essai multicentrique PIHRL confirme que la cure laparoscopique permet une détection peropératoire des hernies controlatérales asymptomatiques supérieure à la voie inguinale classique, réduisant le risque de réintervention secondaire. Le taux de récidive et les complications sont comparables entre les deux voies.",
     "En pratique : privilégier la laparoscopie pour la cure de hernie inguinale pédiatrique — la détection systématique des hernies controlatérales asymptomatiques justifie cette approche, particulièrement chez le jeune enfant."),

    # SCORE 6
    ("08f932e0",
     "STING unilatéral dans le RVU : risque de reflux controlatéral de novo (~15 %)",
     "Cette méta-analyse quantifie le risque de RVU controlatéral de novo après STING unilatéral, survenant dans environ 15 % des cas selon les séries. Ce risque doit être intégré dans le conseil préopératoire et justifie une cystographie de contrôle systématique à 3-6 mois post-traitement.",
     "En pratique : informer les familles du risque de RVU controlatéral de novo (~15 %) après STING unilatéral — cystographie de contrôle obligatoire à 3-6 mois."),

    ("0ba7b9d7",
     "Choléstase néonatale : l'algorithme FISPGHAN accélère le diagnostic d'atrésie biliaire",
     "Ce position paper de la Fédération Internationale des Sociétés de Gastroentérologie Pédiatrique formalise un algorithme en 3 étapes centré sur l'élimination précoce de l'atrésie biliaire, avec l'échographie biliaire, la carte colorimétrique des selles et la GGT comme premiers niveaux d'alerte.",
     "À retenir : tout nouveau-né ictérique à J14 avec selles décolorées ou GGT élevée doit être adressé sans délai pour bilan d'atrésie biliaire — le délai au Kasai est le premier déterminant du pronostic."),

    ("0d5dc101",
     "Malformations lymphatiques pédiatriques : le lauromacrogol est une alternative efficace au pingyangmycin",
     "Cet ECR démontre que la sclérothérapie à la mousse de lauromacrogol guidée par échographie est non-inférieure au pingyangmycin dans les malformations lymphatiques pédiatriques, avec un profil de tolérance local favorable et une disponibilité plus large en Europe.",
     "En pratique : le lauromacrogol est une alternative efficace au pingyangmycin pour la sclérothérapie des malformations lymphatiques pédiatriques — à privilégier en Europe où le pingyangmycin n'est pas disponible."),

    ("0e7ececf",
     "Chirurgie gynécologique robotique pédiatrique : résultats préliminaires favorables, indications en cours de définition",
     "Cette méta-analyse sur la chirurgie gynécologique robot-assistée chez l'enfant (kystes ovariens, DSD, anomalies müllériennes) montre une faisabilité favorable dans les centres spécialisés avec des avantages ergonomiques pour la chirurgie pelvienne profonde. Les durées opératoires restent plus longues que la laparoscopie conventionnelle.",
     "En pratique : la robotique gynécologique pédiatrique est en phase d'émergence — réserver aux centres à haut volume pour les malformations complexes nécessitant une épargne maximale du tissu fonctionnel."),

    ("155406c1",
     "Hyperactivité vésicale réfractaire chez l'enfant : le TENS est efficace en deuxième ligne",
     "Cette méta-analyse de 9 ECR démontre que la neuromodulation transcutanée (TENS) réduit significativement la fréquence mictionnelle et les épisodes d'urgence dans l'hyperactivité vésicale réfractaire de l'enfant, avec un profil de tolérance excellent sans effets secondaires systémiques.",
     "En pratique : proposer le TENS comme option de deuxième ligne dans l'hyperactivité vésicale de l'enfant résistant aux anticholinergiques — technique non invasive, bien tolérée et documentée dans 9 ECR."),

    ("1ce09ebb",
     "Hypoxémie post-anesthésique en chirurgie pédiatrique : les facteurs de risque sont identifiables en préopératoire",
     "Cette méta-analyse identifie l'âge <2 ans, l'obésité, les antécédents respiratoires et les chirurgies thoraciques ou abdominales comme principaux prédicteurs d'hypoxémie post-anesthésique en chirurgie pédiatrique non cardiaque, permettant une stratification du risque dès l'évaluation préopératoire.",
     "En pratique : stratifier le risque d'hypoxémie post-anesthésique dès la consultation préopératoire — renforcer la surveillance en SSPI et adapter la durée de monitorage selon le profil de risque."),

    ("24a46d4b",
     "Cryoablation intercostale lors du MIRPE : séquelles sensitives à long terme dans une proportion significative de patients",
     "Cette étude prospective multicentrique documente un risque non négligeable d'hypoesthésie ou d'allodynie pariétale thoracique persistante après cryoablation intercostale lors du MIRPE, avec une prévalence significativement plus élevée versus chirurgie sans cryoablation et une récupération partielle à 12 mois.",
     "En pratique : informer les patients des risques de séquelles sensitives à long terme avant cryoablation intercostale lors du MIRPE — réévaluer la systématisation de cette technique au regard du bénéfice analgésique à court terme."),

    ("25f3ac41",
     "Valves de l'urètre postérieur : le score PURK identifie les enfants à risque d'insuffisance rénale terminale",
     "Le score PURK, validé sur une cohorte internationale, identifie à la naissance et dans l'enfance les patients porteurs de valves de l'urètre postérieur qui progresseront vers l'insuffisance rénale terminale. Les variables intégrées (créatinine nadir, âge au diagnostic, grade de reflux associé) permettent une stratification précoce du risque rénal.",
     "En pratique : calculer le score PURK pour chaque enfant avec valves de l'urètre postérieur — les patients à score élevé doivent être orientés en néphropédiatrie dès la prise en charge initiale."),

    ("2beb0633",
     "Syndrome d'insensibilité aux androgènes : la gonadectomie prophylactique doit être individualisée selon le type (CAIS <2% vs PAIS ~15%)",
     "Le risque de malignité gonadique diffère radicalement entre AIS complet (CAIS, <2%) et partiel (PAIS, ~15%). Cette revue systématique remet en question la gonadectomie prophylactique systématique dans le CAIS, où la gonade produit des œstrogènes endogènes et où une surveillance ciblée est préférable.",
     "En pratique : ne pas systématiser la gonadectomie dans le CAIS — risque de malignité bas (<2%), les gonades produisent des œstrogènes endogènes utiles. Réserver la gonadectomie au PAIS après discussion pluridisciplinaire avec la famille."),

    ("2d2859a1",
     "Énémas continents antégrades (ACE) dans les malformations anorectales et Hirschsprung : résultats hétérogènes, consensus nécessaire",
     "Cette méta-analyse met en évidence une hétérogénéité majeure dans la définition du succès des ACE entre les études en chirurgie colorectale pédiatrique. Le taux de continence sociale varie de 40 à 85 % selon les séries, reflétant des différences de sélection et de critères d'évaluation.",
     "En pratique : les ACE sont une option valide pour l'incontinence réfractaire post-chirurgie colorectale pédiatrique — le succès dépend fortement de la sélection des patients et de la compliance familiale au programme."),

    ("2fcb0466",
     "Paralysie récurrentielle post-atrésie de l'œsophage : incidence sous-estimée à 10-15 % si recherchée systématiquement",
     "Cette méta-analyse documente une incidence de paralysie récurrentielle nettement plus élevée qu'attendu (jusqu'à 10-15 %) si recherchée par nasofibroscopie systématique, versus 3-5 % si évaluée sur la clinique seule. Le nerf récurrent gauche est particulièrement à risque lors de la dissection de la fistule.",
     "En pratique : réaliser une nasofibroscopie laryngée systématique en post-opératoire de cure d'atrésie de l'œsophage — paralysie récurrentielle infraclinique fréquente, évaluation déglutition par orthophonie avant alimentation orale."),

    ("312b112a",
     "CPAM sévère avec hydrops : le shunt Somatex™ donne des résultats comparables aux dispositifs Cook™ et Rocket™",
     "Cette étude multicentrique évalue les résultats postnataux du shunt thoracoamniotique Somatex™ pour les CPAM fœtales sévères avec hydrops. Les taux de survie et résultats chirurgicaux postnataux sont comparables aux séries de référence avec les dispositifs de comparaison, avec un taux de déplacement similaire.",
     "En pratique : le Somatex™ est une alternative valide aux dispositifs Cook™ et Rocket™ pour le shunt thoracoamniotique des CPAM avec hydrops — choix selon disponibilité et expérience du centre de médecine fœtale."),

    ("36fe6296",
     "Hernie diaphragmatique congénitale : qualité de vie altérée dans les domaines respiratoire, nutritionnel et psychologique à long terme",
     "Cette méta-analyse sur la qualité de vie après réparation de CDH révèle des altérations persistantes dans les domaines respiratoire, nutritionnel, neurodéveloppemental et psychologique, même chez les enfants survivants sans complications majeures. Ces résultats justifient un suivi multidisciplinaire prolongé.",
     "En pratique : structurer le suivi multidisciplinaire des enfants CDH au-delà de la période néonatale — les dimensions nutritionnelle, pulmonaire et psychologique restent altérées à moyen et long terme."),

    ("3805af7f",
     "Fluorescence ICG en chirurgie néonatale : identification des structures anatomiques améliorée dans les procédures complexes",
     "Cette revue systématique évalue l'utilité de la fluorescence ICG dans les procédures chirurgicales néonatales (atrésie biliaire, NEC, malformations intestinales). La technique améliore la visualisation de la vascularisation intestinale et des voies biliaires avec un impact potentiel sur la décision chirurgicale.",
     "En pratique : étendre la fluorescence ICG aux chirurgies néonatales complexes — les protocoles sont en cours de standardisation, la technique est disponible sur le matériel laparoscopique compatible."),

    ("38b4422a",
     "Cicatrices rénales dans le RVU : les biomarqueurs urinaires ne remplacent pas encore la scintigraphie DMSA",
     "Cette méta-analyse évalue la précision diagnostique des biomarqueurs (NGAL, KIM-1, β2-microglobuline) pour les cicatrices rénales dans le RVU. Malgré des résultats prometteurs, les données restent insuffisantes pour remplacer la DMSA comme standard diagnostique.",
     "En pratique : les biomarqueurs urinaires ne remplacent pas encore la DMSA dans le bilan des cicatrices rénales — potentiellement utiles pour sélectionner les patients qui bénéficieront le plus de l'imagerie isotopique."),

    ("398f87e5",
     "Maladie de Basedow pédiatrique : préférer la thyroïdectomie avant 10 ans, iode radioactif chez l'adolescent",
     "Cette méta-analyse montre que la thyroïdectomie totale offre un taux de rémission plus rapide et prévisible dans la maladie de Basedow pédiatrique, tandis que l'iode radioactif présente un risque théorique mutagène à prendre en compte avant la puberté. La majorité des centres de référence préfèrent la chirurgie avant 10 ans.",
     "En pratique : préférer la thyroïdectomie totale avant 10 ans pour la maladie de Basedow réfractaire au traitement médical — réserver l'iode radioactif aux adolescents proches de l'âge adulte après discussion multidisciplinaire."),

    ("49672fd9",
     "Extrophie vésicale : morbidité psychiatrique significative qui justifie un suivi psychologique intégré",
     "Cette méta-analyse avec étude cas-témoins documente une prévalence élevée de troubles psychiatriques (anxiété, dépression, trouble de l'adaptation) chez les patients porteurs d'extrophie vésicale, supérieure à la population générale pédiatrique.",
     "En pratique : intégrer un suivi psychologique systématique dans le programme de soins des enfants porteurs d'extrophie vésicale — la morbidité psychiatrique est documentée et sous-dépistée dans cette population."),

    ("5b3ace33",
     "Robotique single-port versus multi-port en chirurgie pédiatrique : résultats périopératoires comparables",
     "Cette méta-analyse montre des résultats périopératoires comparables entre robotique single-port et multi-port en pédiatrie en termes de complications et durée d'hospitalisation. La technique SP offre un avantage cosmétique évident mais nécessite une courbe d'apprentissage plus longue.",
     "En pratique : la chirurgie robotique single-port est une option valide dans les centres experts pour des procédures pédiatriques sélectionnées — résultats équivalents au multi-port avec avantage cosmétique documenté."),

    ("663c66ae",
     "Kyste cholédoque type I : la résection complète de la voie intrapancréatique réduit le risque carcinologique",
     "Cette étude multicentrique démontre que la résection complète incluant la voie biliaire intrapancréatique (REC) réduit significativement le risque de récidive et de transformation maligne à long terme par rapport à la résection subtotale dans les kystes cholédoques type I avec atteinte IPBD.",
     "En pratique : viser une résection complète de la voie biliaire intrapancréatique dans les kystes cholédoques type I avec atteinte IPBD — le risque carcinologique à long terme justifie la REC malgré une morbidité opératoire plus élevée."),

    ("6e49b8c6",
     "Traumatisme rénal de haut grade pédiatrique : le protocole TRICK standardise la surveillance et la reprise d'activité",
     "Le consortium TRICK propose des recommandations standardisées pour la surveillance et la reprise d'activité physique après traumatisme rénal de haut grade (grade III-V) chez l'enfant, basées sur des données de cohorte prospectives documentant les complications tardives.",
     "En pratique : appliquer le protocole TRICK pour le suivi post-traumatisme rénal de haut grade pédiatrique — délais de reprise sportive et critères de surveillance définis par consensus international."),

    ("723c421b",
     "Prophylaxie antibiotique post-pyéloplastie pédiatrique : bénéfice non démontré en dehors des patients à risque",
     "Cette méta-analyse ne montre pas de réduction significative des infections urinaires post-opératoires avec une prophylaxie antibiotique systématique après pyéloplastie pour jonction pyélo-urétérale pédiatrique, remettant en question la prescription systématique.",
     "En pratique : ne pas prescrire d'antibiothérapie prophylactique systématique après pyéloplastie pédiatrique — la réserver aux patients avec RVU associé ou antécédents d'IU récidivantes."),

    ("753dfe4d",
     "Urétérocèle pédiatrique : dysfonction mictionnelle résiduelle dans ~1/3 des cas après traitement",
     "Cette méta-analyse montre une prévalence de dysfonction mictionnelle persistante dans environ un tiers des cas à distance du traitement chirurgical ou endoscopique de l'urétérocèle pédiatrique, justifiant un suivi urodynamique systématique post-traitement.",
     "En pratique : organiser un bilan urodynamique de contrôle systématique à 12 mois après traitement d'urétérocèle pédiatrique — la dysfonction mictionnelle résiduelle est fréquente et nécessite une prise en charge spécifique."),

    ("773506f3",
     "Dialyse péritonéale pédiatrique : la pose laparoscopique du cathéter réduit le taux de dysfonction",
     "Cette méta-analyse démontre que la mise en place laparoscopique du cathéter de Tenckhoff est associée à un taux de dysfonction précoce et de migration plus faible qu'avec la technique ouverte, avec une durée de survie du cathéter plus longue.",
     "En pratique : privilégier la mise en place laparoscopique du cathéter de dialyse péritonéale chez l'enfant — réduction du taux de dysfonction et de migration, amélioration de la durée de vie du cathéter."),

    ("78ae6967",
     "Transition urologie pédiatrique → adulte : les recommandations EAU/ESPU définissent un cadre structuré",
     "Les recommandations EAU/ESPU définissent les protocoles de transfert vers l'urologie adulte pour les principales pathologies congénitales (valves urètre postérieur, RVU opéré, extrophie, spina bifida, hypospadias complexe), avec une transition à anticiper dès 14 ans.",
     "À retenir : initier la préparation à la transition en urologie pédiatrique dès 14 ans — un transfert non planifié à 18 ans expose à une rupture de soins délétère pour les pathologies congénitales complexes."),

    ("7ace6914",
     "Fluorescence ICG en urologie pédiatrique : bénéfice documenté pour la pyéloplastie et la surrénalectomie",
     "Cette méta-analyse montre un bénéfice démontré de la fluorescence ICG pour la visualisation des voies urinaires lors des pyéloplasties laparoscopiques et robot-assistées, et pour la cartographie vasculaire en surrénalectomie. L'application à la réimplantation urétérale est en cours d'évaluation.",
     "En pratique : intégrer la fluorescence ICG dans les pyéloplasties et surrénalectomies pédiatriques complexes — bénéfice documenté sur la visualisation anatomique en temps réel."),

    ("7cfb37ec",
     "Atrésie de l'œsophage : qualité de vie altérée dans les domaines digestif et respiratoire — suivi multidisciplinaire jusqu'à l'âge adulte",
     "Cette méta-analyse documente des altérations persistantes de la qualité de vie après cure d'atrésie de l'œsophage, notamment dans les domaines de la déglutition et de la fonction pulmonaire. Ces résultats soulignent la nécessité d'un suivi multidisciplinaire organisé bien au-delà de la petite enfance.",
     "En pratique : structurer un suivi multidisciplinaire à long terme pour tous les patients opérés d'atrésie de l'œsophage — ORL, gastroentérologue et pneumologue pédiatrique jusqu'à l'âge adulte."),

    ("7fd15289",
     "Kyste cholédoque type I avec atteinte intrapancréatique : la résection complète réduit le risque de transformation maligne",
     "Cette étude multicentrique confirme que la résection complète incluant la voie biliaire intrapancréatique est associée à un risque de récidive biliaire et de transformation maligne significativement plus faible à 5 ans que la résection subtotale. La morbidité est plus élevée mais acceptable dans les centres spécialisés.",
     "En pratique : discuter la résection complète de la voie intrapancréatique en RCP de référence pour les kystes cholédoques type I — risque oncologique justifie l'approche radicale malgré la morbidité accrue."),

    ("84958f73",
     "Hernie inguinale récidivante pédiatrique : la LPEC évite le tissu cicatriciel inguinal et donne de bons résultats",
     "Cette étude multicentrique démontre que la LPEC est efficace pour les hernies inguinales récidivantes, avec un taux de récidive après LPEC comparable à la voie ouverte. La voie laparoscopique est avantageuse pour les récidives car elle évite la dissection dans un espace cicatriciel inguinal.",
     "En pratique : préférer la LPEC pour la cure des hernies inguinales récidivantes pédiatriques — contourne le tissu cicatriciel inguinal et réduit le risque de complications vasculo-spermatiques."),

    ("87d043d9",
     "Tératome sacrococcygien : composante intrapelvienne et histologie immature prédisent la récidive",
     "Cette étude rétrospective multicentrique (5 centres) identifie la localisation intrapelvienne et l'immaturité histologique comme principaux prédicteurs de récidive dans le tératome sacrococcygien fœtal/néonatal, permettant une stratification du suivi post-opératoire.",
     "En pratique : intensifier la surveillance post-opératoire (AFP, IRM) dans les tératomes sacrococcygiens avec composante intrapelvienne ou histologie immature — adapter le protocole selon les facteurs pronostiques identifiés."),

    ("883af281",
     "MICI pédiatriques : accès aux biothérapies systématiquement en retard sur les adultes",
     "Ce position paper ESPGHAN-NASPGHAN documente le retard structurel d'accès aux thérapies avancées pour les enfants atteints de MICI, dû aux délais d'inclusion pédiatrique dans les essais pivots. Des solutions sont proposées : extrapolation réglementaire, études pharmacocinétiques pédiatriques, registres de cohorte.",
     "En pratique : documenter les cas pédiatriques MICI sans accès aux biothérapies approuvées pour les adultes — les données de vie réelle sont essentielles pour accélérer les approbations pédiatriques EMA et FDA."),

    ("91c77ee5",
     "Fistule gastrocutanée post-gastrostomie : fermeture spontanée dans ~75 % des cas avec traitement médical séquentiel",
     "Cette étude prospective montre qu'une approche séquentielle non chirurgicale (IPP haute dose, nitrate d'argent topique, puis colle de fibrine) permet la fermeture spontanée de la fistule gastrocutanée persistante dans environ 70-80 % des cas chez l'enfant. La chirurgie reste nécessaire pour les fistules persistant après 8-12 semaines.",
     "En pratique : traiter la fistule gastrocutanée post-gastrostomie par IPP haute dose et nitrate d'argent avant toute fermeture chirurgicale — cicatrisation spontanée dans la majorité des cas en 4-8 semaines."),

    ("9446de39",
     "Orchidopexie de Fowler-Stephens au Royaume-Uni : taux d'atrophie de 10-15 % à 2 ans, cohérent avec les standards internationaux",
     "Cette étude rétrospective dans 6 centres tertiaires britanniques documente les résultats de l'orchidopexie de Fowler-Stephens en deux temps, avec un taux d'atrophie testiculaire secondaire de 10-15 % à 2 ans — cohérent avec les données internationales.",
     "En pratique : les résultats du registre britannique (10-15 % d'atrophie à 2 ans) sont la référence de benchmark pour l'orchidopexie de Fowler-Stephens — documenter systématiquement les résultats à long terme dans son centre."),

    ("96787d9d",
     "Transfusion plaquettaire restrictive en néonatologie chirurgicale : la stratégie PlaNeT-2 (seuil 25×10⁹/L) réduit la mortalité",
     "Cette étude démontre qu'appliquer la stratégie restrictive de l'essai PlaNeT-2 (seuil transfusionnel de 25×10⁹/L au lieu de 50×10⁹/L) en néonatologie chirurgicale est associée à une réduction de la mortalité et des hémorragies intraventriculaires, sans augmentation du risque hémorragique per-opératoire.",
     "À retenir : appliquer le seuil transfusionnel plaquettaire restrictif PlaNeT-2 (25×10⁹/L) en néonatologie chirurgicale — sauf chirurgie à haut risque hémorragique ou symptomatologie active."),

    ("993af208",
     "Hypospadias : le PRP autologue réduit les fistules urétrocutanées — bénéfice plus marqué dans les formes proximales",
     "Cette méta-analyse d'avril 2026 intégrant les ECR les plus récents confirme que le PRP autologue réduit significativement le taux de fistule urétrocutanée dans la réparation chirurgicale de l'hypospadias pédiatrique, avec un bénéfice plus marqué dans les hypospadias proximaux et les réparations secondaires.",
     "En pratique : évaluer l'intégration du PRP autologue dans les réparations d'hypospadias — la méta-analyse d'avril 2026 précise les sous-groupes qui bénéficient le plus de cette technique adjuvante."),

    ("9f0dc462",
     "Chirurgie thoracique robotique pédiatrique : faisabilité démontrée, avantages pour les dissections complexes",
     "Cette revue systématique et méta-analyse sur la chirurgie thoracique robot-assistée chez l'enfant montre des résultats périopératoires favorables avec une conversion moins fréquente dans les dissections complexes, malgré des durées opératoires plus longues reflétant la courbe d'apprentissage.",
     "En pratique : la robotique thoracique pédiatrique est à considérer pour les résections complexes (médiastin, lobectomies dans des thorax petits) dans les centres experts — données de survie à long terme pour les tumeurs malignes encore limitées."),

    ("a33b44d0",
     "Réalité virtuelle pour la chirurgie d'ongle incarné chez l'enfant : douleur et anxiété réduites sous anesthésie locale",
     "Cet ECR démontre que la réalité virtuelle immersive réduit significativement la douleur (échelle numérique) et l'anxiété comportementale (fréquence cardiaque, FLACC) pendant la chirurgie d'ongle incarné sous anesthésie locale chez l'enfant, sans formation spécifique du personnel.",
     "En pratique : utiliser la réalité virtuelle immersive pour les actes ambulatoires pédiatriques sous anesthésie locale — réduction documentée de la douleur et du stress dans cet ECR, applicable sans formation spécifique."),

    ("a9ad1b08",
     "Hernie inguinale pédiatrique : la technique préférée du chirurgien influence le taux de récidive",
     "Cette étude de cohorte multicentrique montre que le taux de récidive varie significativement selon la technique préférée du chirurgien, indépendamment des caractéristiques du patient. Les chirurgiens pratiquant majoritairement la laparoscopie obtiennent de meilleurs résultats avec cette voie, et inversement.",
     "En pratique : la technique et le volume du chirurgien sont des déterminants majeurs des résultats dans la hernie inguinale pédiatrique — orienter vers des chirurgiens à haut volume quelle que soit la voie d'abord."),

    ("aa72eb48",
     "Kyste cholédoque pédiatrique : la laparoscopie réduit les complications infectieuses selon le registre multicentrique japonais",
     "Cette étude multicentrique (région Kyushu) confirme que la résection laparoscopique du kyste cholédoque est associée à moins de complications infectieuses post-opératoires et une durée d'hospitalisation plus courte, sans différence sur les complications biliaires tardives à 2 ans.",
     "En pratique : la résection laparoscopique du kyste cholédoque pédiatrique est la voie de référence dans les centres spécialisés — réduction des complications infectieuses et de la durée d'hospitalisation."),

    ("ac78b12d",
     "Brûlures superficielles pédiatriques de 2e degré : le pansement subvacuum est équivalent au Mepilex XT",
     "Cet ECR multicentrique de non-infériorité montre des critères de cicatrisation comparables (délai de réépithélialisation, douleur lors des changements, résultat cosmétique) entre le pansement subvacuum et le Mepilex®XT dans les brûlures superficielles de 2e degré chez l'enfant.",
     "En pratique : le pansement subvacuum est une alternative valide au Mepilex XT dans les brûlures superficielles pédiatriques — à évaluer selon les disponibilités locales, avec des résultats cliniques équivalents."),

    ("c0b10706",
     "Réalité virtuelle dans le MIRPE : réduction de l'anxiété et des antalgiques post-opératoires chez l'adolescent",
     "Cet ECR sur la réalité virtuelle immersive lors du MIRPE chez l'adolescent démontre une réduction significative de l'anxiété préopératoire et un effet modulateur sur la consommation d'antalgiques dans les 24 premières heures.",
     "En pratique : intégrer la réalité virtuelle dans le protocole péri-opératoire du MIRPE — réduction de l'anxiété et des antalgiques pour des adolescents souvent appréhensifs face à cette chirurgie."),

    ("c2308a39",
     "Calculs vésicaux pédiatriques : PCCL supérieure à la TUCL pour les calculs >30 mm",
     "Cet ECR montre des taux de libération des calculs équivalents entre PCCL et TUCL pour les calculs de taille intermédiaire (10-30 mm), mais une supériorité de la PCCL pour les calculs >30 mm. La TUCL expose à un taux plus élevé de complications urétérales chez le jeune garçon.",
     "En pratique : choisir la PCCL pour les calculs vésicaux >30 mm chez l'enfant — TUCL à privilégier pour les calculs <15 mm chez la fille ou les enfants plus grands, en tenant compte du risque de traumatisme urétral."),

    ("c3499b3d",
     "Génitoplastie féminisante dans les DSD : la sensibilité clitoridienne est préservée avec la technique tissue-sparing",
     "Cette étude multicentrique documente la préservation de la sensibilité clitoridienne chez la majorité des patients opérés selon une technique tissue-sparing dans les troubles du développement sexuel. Ces données sont importantes pour le counseling préopératoire et la discussion éthique sur le timing des interventions.",
     "En pratique : informer les familles et les patientes DSD que la clitoroplastie tissue-sparing préserve la sensibilité clitoridienne dans la majorité des cas — données multicentriques disponibles pour le counseling."),

    ("c5b076b1",
     "Omphalocèle géante : l'hypoplasie pulmonaire détermine le pronostic — évaluation dès le prénatal",
     "Cette revue systématique identifie l'hypoplasie pulmonaire et l'hypertension pulmonaire associées comme déterminants majeurs de la mortalité néonatale dans l'omphalocèle géante, indépendamment de la technique de fermeture. L'évaluation pulmonaire prénatale influence directement la stratégie de prise en charge.",
     "En pratique : évaluer systématiquement la composante pulmonaire dès le diagnostic prénatal d'omphalocèle géante — le pronostic respiratoire détermine le lieu d'accouchement et la stratégie de fermeture différée versus précoce."),

    ("ce58c179",
     "Infections post-MIRPE : les facteurs de risque sont identifiables pour adapter la prophylaxie",
     "Cette étude multicentrique (10 centres) identifie les facteurs de risque chirurgicaux (durée d'intervention, nombre de barres) et cliniques (obésité, antécédents cutanés) qui prédisposent aux infections de matériel après MIRPE, permettant d'affiner les protocoles prophylactiques.",
     "En pratique : identifier les patients MIRPE à risque infectieux élevé pour adapter la durée d'antibioprophylaxie et le suivi post-opératoire — l'obésité et une chirurgie prolongée sont les principaux facteurs modifiables."),

    ("d1889fdc",
     "Sténoses œsophagiennes caustiques pédiatriques : mitomycine C et corticoïdes réduisent les récidives de sténose",
     "Cet ECR compare la mitomycine C topique versus les corticoïdes intralésionnels comme traitement adjuvant des sténoses œsophagiennes caustiques pédiatriques. Les deux traitements réduisent le nombre de séances de dilatation et l'intervalle entre deux dilatations, sans différence significative entre eux.",
     "En pratique : associer un traitement adjuvant (mitomycine C ou corticoïdes intralésionnels) aux dilatations dans les sténoses œsophagiennes caustiques réfractaires — les deux options sont efficaces avec un profil de tolérance comparable."),
]

def main():
    conn = psycopg2.connect(DB)
    cur = conn.cursor()

    ok = 0
    skipped = 0
    errors = []

    for prefix, titre, resume, impact in UPDATES:
        # Ignorer les items marqués None (déjà bons)
        if titre is None and resume is None and impact is None:
            skipped += 1
            continue

        # Récupérer l'item
        cur.execute(
            "SELECT id, tri_json FROM items WHERE candidate_id::text LIKE %s AND specialty_slug='chirurgie-pediatrique'",
            (prefix + '%',)
        )
        rows = cur.fetchall()
        if not rows:
            errors.append(f"NOT FOUND: {prefix}")
            continue
        if len(rows) > 1:
            errors.append(f"MULTIPLE ({len(rows)}): {prefix}")
            continue

        item_id, tj = rows[0]
        if isinstance(tj, str):
            tj = json.loads(tj)

        # Mettre à jour les champs
        if titre is not None:
            tj['titre_court'] = titre
        if resume is not None:
            tj['resume'] = resume
        if impact is not None:
            tj['impact_pratique'] = impact

        cur.execute(
            "UPDATE items SET tri_json = %s WHERE id = %s",
            (json.dumps(tj, ensure_ascii=False), item_id)
        )
        ok += 1

    conn.commit()
    conn.close()

    print(f"✅ Mis à jour : {ok}")
    print(f"⏭️  Ignorés (déjà bons) : {skipped}")
    if errors:
        print(f"❌ Erreurs :")
        for e in errors:
            print(f"  {e}")
    else:
        print("✅ Aucune erreur")

if __name__ == '__main__':
    main()
