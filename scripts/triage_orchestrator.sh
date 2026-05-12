#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MedNews — Orchestrateur de triage automatique
#
# 3 créneaux par jour :
#   Slot 1 — 05h00 UTC : triage global + spécialités 1-12  (4 comptes × 3 spés)
#   Slot 2 — 10h00 UTC : spécialités 13-24                 (4 comptes × 3 spés)
#   Slot 3 — 16h00 UTC : spécialités 25-36                 (4 comptes × 3 spés)
#
# ~5-6h de gap entre créneaux → rate limits Pro régénérés entre chaque slot.
#
# Backlog : si le slot N-1 n'a pas pu terminer (rate limit 5h atteint),
# les spécialités restantes sont détectées au démarrage du slot N et traitées
# en priorité (round-robin sur les 4 comptes) avant les spés normales du slot N.
#
# Usage:
#   ./triage_orchestrator.sh --slot 1        # créneau du matin
#   ./triage_orchestrator.sh --slot 2        # créneau de midi
#   ./triage_orchestrator.sh --slot 3        # créneau du soir
#   ./triage_orchestrator.sh --slot 1 --dry-run
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="/opt/mednews"
LOG_DIR="/var/log/mednews"
PAUSE_BETWEEN_SESSIONS=120  # secondes entre deux sessions claude (rate limit)

# ─── Arguments ───────────────────────────────────────────────────────────────
SLOT=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --slot) SLOT="$2"; shift 2 ;;
        --dry-run) DRY_RUN="--dry-run"; shift ;;
        *) echo "Usage: $0 --slot 1|2|3 [--dry-run]"; exit 1 ;;
    esac
done

if [[ "$SLOT" != "1" && "$SLOT" != "2" && "$SLOT" != "3" ]]; then
    echo "ERREUR : --slot doit être 1, 2 ou 3"
    exit 1
fi

# ─── Lock par slot — empêche deux runs simultanés du même créneau ────────────
LOCKFILE="/tmp/mednews_triage_slot${SLOT}.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SKIP — slot $SLOT déjà en cours (lock $LOCKFILE)"
    exit 0
fi

# Chargement DATABASE_URL depuis .env
# shellcheck disable=SC1091
[[ -f "$REPO_DIR/.env" ]] && { set -a; source "$REPO_DIR/.env"; set +a; }

mkdir -p "$LOG_DIR"
chmod 1777 "$LOG_DIR"
LOGFILE="$LOG_DIR/slot${SLOT}_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

# ─── Fichiers partagés inter-streams ─────────────────────────────────────────
# FAILED_FILE : spécialités en erreur → redistribuées en post-slot (filet de sécurité)
# QUEUE_FILE  : spécialités restantes d'un stream rate-limité → drainées par les
#               comptes disponibles en temps réel (work-stealing intra-slot)
FAILED_FILE="/tmp/mednews_failed_slot${SLOT}.txt"
QUEUE_FILE="/tmp/mednews_queue_slot${SLOT}.txt"
QUEUE_LOCK="/tmp/mednews_queue_slot${SLOT}.lock"
rm -f "$FAILED_FILE" "$QUEUE_FILE"

# ─── check_count : compte les NEW pour un slug, essaie les 4 comptes en fallback
# Évite le point de défaillance unique sur mednews1 en cas de rate limit.
check_count() {
    local slug="$1"
    local extra_args="${2:-}"   # ex: "--min-age-hours 8"
    for user in mednews1 mednews2 mednews3 mednews4; do
        local cnt
        cnt=$(su - "$user" -c \
            "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py $slug $extra_args" \
            2>/dev/null || true)
        cnt=$(echo "$cnt" | tr -d '[:space:]')
        if [[ "$cnt" =~ ^[0-9]+$ ]]; then
            echo "$cnt"
            return 0
        fi
    done
    log "[check] WARN — tous les comptes ont échoué pour $slug (DB inaccessible ?), supposé 0"
    echo "0"
}

# ─── File partagée : opérations atomiques via flock ──────────────────────────
#
# Invariants certifiables :
#   1. Chaque slug est popped par au plus un stream (exclusion mutuelle flock)
#   2. Aucun slug n'est perdu : ERROR → FAILED_FILE ; restants → QUEUE_FILE
#   3. Un compte idle après sa liste propre draine QUEUE_FILE jusqu'à épuisement
#   4. FAILED_FILE = filet de sécurité post-slot si tous les comptes sont limités

# queue_push_list "$slug1 $slug2 …"
# Ajoute les slugs en fin de file, sans doublons.
queue_push_list() {
    local slugs_str="$1"
    {
        flock -x 200
        for s in $slugs_str; do
            grep -qx "$s" "$QUEUE_FILE" 2>/dev/null || echo "$s" >> "$QUEUE_FILE"
        done
    } 200>"$QUEUE_LOCK"
    log "[queue] push : $slugs_str"
}

# queue_pop → écrit le slug sur stdout, ou "" si file vide
# Atomique : lit + supprime la première ligne en une seule section lockée.
queue_pop() {
    {
        flock -x 200
        local slug=""
        if [[ -s "$QUEUE_FILE" ]]; then
            slug=$(head -1 "$QUEUE_FILE")
            tail -n +2 "$QUEUE_FILE" > "${QUEUE_FILE}.tmp"
            mv "${QUEUE_FILE}.tmp" "$QUEUE_FILE"
        fi
        echo "$slug"
    } 200>"$QUEUE_LOCK"
}

# ─── run_one_specialty : exécute une session claude pour un slug ──────────────
# Retour : 0=succès  1=erreur (rate limit ou crash)  2=skip (0 NEW)
run_one_specialty() {
    local user="$1"
    local slug="$2"
    local label="${3:- }"   # " (queue)" ou "       "

    local new_count
    new_count=$(check_count "$slug")

    if [[ "${new_count:-0}" -eq 0 ]]; then
        log "[$user] SKIP${label}  $slug — 0 candidats NEW"
        return 2
    fi

    log "[$user] START${label} $slug — $new_count candidats NEW"

    if [[ -n "$DRY_RUN" ]]; then
        log "[$user] DRY-RUN${label} $slug"
        return 0
    fi

    local slug_log="$LOG_DIR/${slug}_$(date +%Y%m%d).log"
    su - "$user" -c \
        "cd $REPO_DIR && claude -p 'lance $slug' --dangerously-skip-permissions --output-format text --permission-prompt-tool stdio" \
        < /dev/null >> "$slug_log" 2>&1
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log "[$user] DONE${label}  $slug"
        return 0
    else
        log "[$user] ERROR${label} $slug — voir $slug_log"
        echo "$slug" >> "$FAILED_FILE"
        return 1
    fi
}

# ─── Répartition : 4 comptes × 3 slots × 3 spécialités = 36 ─────────────────
#
# Compte        Slot 1              Slot 2                  Slot 3
# mednews1      anesthesiologie     geriatrie               neurologie
#               biologiste          gynecologie             oncologie
#               cardiologie         hematologie             ophtalmologie
#
# mednews2      chirurgie-card.     infectiologie           orl
#               chirurgie-ortho.    infirmiers              pediatrie
#               chirurgie-pedia.    kinesitherapie          pharmacien
#
# mednews3      chirurgie-plast.    medecine-generale       pneumologie
#               chirurgie-thor.     medecine-interne        psychiatrie
#               chirurgie-vasc.     medecine-physique       radiologie
#
# mednews4      dermatologie        medecine-urgences       rhumatologie
#               endocrinologie      nephrologie             sage-femme
#               gastro-enterologie  neurochirurgie          urologie

declare -A SLOT_SPECIALTIES

SLOT_SPECIALTIES["mednews1_1"]="anesthesiologie biologiste cardiologie"
SLOT_SPECIALTIES["mednews1_2"]="geriatrie gynecologie hematologie"
SLOT_SPECIALTIES["mednews1_3"]="neurologie oncologie ophtalmologie"

SLOT_SPECIALTIES["mednews2_1"]="chirurgie-cardiaque chirurgie-orthopedique chirurgie-pediatrique"
SLOT_SPECIALTIES["mednews2_2"]="infectiologie infirmiers kinesitherapie"
SLOT_SPECIALTIES["mednews2_3"]="orl pediatrie pharmacien"

SLOT_SPECIALTIES["mednews3_1"]="chirurgie-plastique chirurgie-thoracique chirurgie-vasculaire"
SLOT_SPECIALTIES["mednews3_2"]="medecine-generale medecine-interne medecine-physique"
SLOT_SPECIALTIES["mednews3_3"]="pneumologie psychiatrie radiologie"

SLOT_SPECIALTIES["mednews4_1"]="dermatologie endocrinologie gastro-enterologie"
SLOT_SPECIALTIES["mednews4_2"]="medecine-urgences nephrologie neurochirurgie"
SLOT_SPECIALTIES["mednews4_3"]="rhumatologie sage-femme urologie"

# ─── Stream : triage séquentiel d'une liste de spécialités ──────────────────
#
# Phase 1 — liste propre : traite les spécialités assignées à ce compte.
#   Si rate limit détecté (ERROR) : pousse les spécialités RESTANTES dans
#   QUEUE_FILE et s'arrête immédiatement (les prochaines échoueraient aussi).
#
# Phase 2 — drain file partagée : si phase 1 terminée sans erreur, draine
#   QUEUE_FILE jusqu'à épuisement (work-stealing des comptes rate-limités).
#   Arrêt dès la première erreur (ce compte est maintenant limité à son tour).
#
# Garantie : toute spécialité finit dans DONE, SKIP, ou FAILED_FILE.
run_stream() {
    local user="$1"
    local specialties_str="$2"
    read -ra specialties <<< "$specialties_str"
    local done=0 skipped=0 errors=0

    log "[$user] Slot $SLOT — ${#specialties[@]} spécialités : ${specialties[*]}"

    # ── Phase 1 : liste propre ────────────────────────────────────────────────
    local i=0
    for slug in "${specialties[@]}"; do
        run_one_specialty "$user" "$slug"
        local rc=$?
        case $rc in
            0)
                ((done++)) || true
                [[ -z "$DRY_RUN" ]] && sleep "$PAUSE_BETWEEN_SESSIONS"
                ;;
            2) ((skipped++)) || true ;;
            1)
                ((errors++)) || true
                # Pousser les spécialités RESTANTES (après slug courant) dans la file
                local remaining=("${specialties[@]:$((i+1))}")
                if [[ ${#remaining[@]} -gt 0 ]]; then
                    queue_push_list "${remaining[*]}"
                    log "[$user] Rate limit — ${#remaining[@]} spé(s) transférée(s) vers la file : ${remaining[*]}"
                fi
                break  # Arrêt immédiat — compte indisponible
                ;;
        esac
        ((i++)) || true
    done

    # ── Phase 2 : drain de la file partagée (si compte encore disponible) ────
    if [[ $errors -eq 0 ]]; then
        local q_slug
        while true; do
            q_slug=$(queue_pop)
            q_slug=$(echo "$q_slug" | tr -d '[:space:]')
            [[ -z "$q_slug" ]] && break

            run_one_specialty "$user" "$q_slug" " (queue)"
            local qrc=$?
            case $qrc in
                0)
                    ((done++)) || true
                    [[ -z "$DRY_RUN" ]] && sleep "$PAUSE_BETWEEN_SESSIONS"
                    ;;
                2) ((skipped++)) || true ;;
                1)
                    ((errors++)) || true
                    log "[$user] Rate limit sur file partagée — arrêt drain"
                    break
                    ;;
            esac
        done
    fi

    log "[$user] Terminé — done=$done skipped=$skipped errors=$errors"
}

# ─── Backlog : toutes les spécialités encore en NEW (hors slot courant) ───────
# Scanne les 36 spécialités. Retourne celles qui ont des candidats NEW
# et qui NE SONT PAS dans le slot courant (celles-ci seront traitées normalement).
# Garanti : quelle que soit l'origine du retard (slot N-1, N-2…), elles remontent.

ALL_SLUGS=(
    anesthesiologie biologiste cardiologie
    chirurgie-cardiaque chirurgie-orthopedique chirurgie-pediatrique
    chirurgie-plastique chirurgie-thoracique chirurgie-vasculaire
    dermatologie endocrinologie gastro-enterologie
    geriatrie gynecologie hematologie
    infectiologie infirmiers kinesitherapie
    medecine-generale medecine-interne medecine-physique medecine-urgences
    nephrologie neurochirurgie neurologie
    oncologie ophtalmologie orl
    pediatrie pharmacien pneumologie psychiatrie
    radiologie rhumatologie sage-femme urologie
)

compute_backlog() {
    # Slugs du slot courant — seront traités par les streams normaux
    local current_slugs
    current_slugs=" ${SLOT_SPECIALTIES["mednews1_${SLOT}"]} ${SLOT_SPECIALTIES["mednews2_${SLOT}"]} ${SLOT_SPECIALTIES["mednews3_${SLOT}"]} ${SLOT_SPECIALTIES["mednews4_${SLOT}"]} "

    local backlog=()
    for slug in "${ALL_SLUGS[@]}"; do
        # Sauter les spés du slot courant
        [[ "$current_slugs" == *" $slug "* ]] && continue

        # --min-age-hours 8 : ne considérer comme backlog que les candidats NEW
        # depuis plus de 8h (= un slot complet de 6h + marge).
        # Évite de traiter comme backlog les spés freshly collectées qui attendent
        # simplement leur slot prévu (slots 2 et 3 après une collecte à 1h UTC).
        local cnt
        cnt=$(check_count "$slug" "--min-age-hours 8")
        if [[ "${cnt:-0}" -gt 0 ]]; then
            backlog+=("$slug")
        fi
    done
    echo "${backlog[*]}"
}

# Distribue une liste de slugs en round-robin sur les 4 comptes et les traite
# en parallèle avant de continuer. Bloque jusqu'à ce que tout soit terminé.
run_backlog() {
    local backlog_str="$1"
    read -ra backlog <<< "$backlog_str"
    [[ ${#backlog[@]} -eq 0 ]] && return 0

    local accounts=("mednews1" "mednews2" "mednews3" "mednews4")
    declare -A per_account
    per_account["mednews1"]=""
    per_account["mednews2"]=""
    per_account["mednews3"]=""
    per_account["mednews4"]=""

    local i=0
    for slug in "${backlog[@]}"; do
        local acc="${accounts[$((i % 4))]}"
        per_account[$acc]+=" $slug"
        ((i++)) || true
    done

    log "[backlog] Distribution : mednews1='${per_account[mednews1]}' mednews2='${per_account[mednews2]}' mednews3='${per_account[mednews3]}' mednews4='${per_account[mednews4]}'"

    local pids=()
    for acc in mednews1 mednews2 mednews3 mednews4; do
        local slugs="${per_account[$acc]}"
        [[ -z "${slugs// /}" ]] && continue
        run_stream "$acc" "$slugs" &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done
    log "[backlog] Terminé."
}

# ─── Passe globale (slot 1 uniquement) ───────────────────────────────────────
run_global() {
    local user="mednews1"
    local new_count
    new_count=$(su - "$user" -c \
        "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py global" \
        2>>"$LOGFILE" || echo "0")
    new_count=$(echo "$new_count" | tr -d '[:space:]')

    if [[ "${new_count:-0}" -eq 0 ]]; then
        log "[global] SKIP — 0 candidats NEW dans les sources communes"
        return 0
    fi

    log "[global] START — $new_count candidats NEW (ANSM, HAS, JORF, EMA, FDA…)"

    if [[ -n "$DRY_RUN" ]]; then
        log "[global] DRY-RUN — claude -p 'triage global'"
    else
        su - "$user" -c "cd $REPO_DIR && claude -p 'triage global' --dangerously-skip-permissions --output-format text --permission-prompt-tool stdio" \
            < /dev/null >> "$LOG_DIR/global_$(date +%Y%m%d).log" 2>&1 &
        wait $! || { log "[global] ERREUR (exit $?) — streams spécialités lancés quand même"; return 0; }
        log "[global] DONE"
        sleep "$PAUSE_BETWEEN_SESSIONS"
    fi
}

# ─── Exécution ────────────────────────────────────────────────────────────────
log "════════════════════════════════════════════════"
log "  MedNews triage — Slot $SLOT — $(date '+%Y-%m-%d %H:%M UTC')"
[[ -n "$DRY_RUN" ]] && log "  MODE DRY-RUN"
log "════════════════════════════════════════════════"

# Slot 1 : passe globale en premier (séquentielle)
# || true : un échec du global (rate limit) ne doit pas bloquer les streams spécialités
if [[ "$SLOT" == "1" ]]; then
    run_global || true
fi

# Backlog : toutes les spécialités hors slot courant encore en NEW
log "════════════════════════════════════════════════"
log "  Vérification backlog global (36 spés hors slot $SLOT)…"
BACKLOG=$(compute_backlog)
if [[ -z "${BACKLOG// /}" ]]; then
    log "  Backlog : vide — aucune spécialité en retard."
else
    log "  Backlog : ${BACKLOG}"
    log "  Traitement du backlog avant slot $SLOT…"
    run_backlog "$BACKLOG"
fi
log "════════════════════════════════════════════════"

# 4 streams en parallèle
run_stream mednews1 "${SLOT_SPECIALTIES["mednews1_${SLOT}"]}" &
PID1=$!
run_stream mednews2 "${SLOT_SPECIALTIES["mednews2_${SLOT}"]}" &
PID2=$!
run_stream mednews3 "${SLOT_SPECIALTIES["mednews3_${SLOT}"]}" &
PID3=$!
run_stream mednews4 "${SLOT_SPECIALTIES["mednews4_${SLOT}"]}" &
PID4=$!

wait $PID1; S1=$?
wait $PID2; S2=$?
wait $PID3; S3=$?
wait $PID4; S4=$?

log "════════════════════════════════════════════════"
[[ $S1 -eq 0 ]] && log "  mednews1 : OK" || log "  mednews1 : ERREUR"
[[ $S2 -eq 0 ]] && log "  mednews2 : OK" || log "  mednews2 : ERREUR"
[[ $S3 -eq 0 ]] && log "  mednews3 : OK" || log "  mednews3 : ERREUR"
[[ $S4 -eq 0 ]] && log "  mednews4 : OK" || log "  mednews4 : ERREUR"

# ─── Redistribution des spécialités en erreur ────────────────────────────────
# Les spécialités qui ont échoué (rate limit, crash) pendant les streams sont
# relancées immédiatement en round-robin sur les 4 comptes, sans attendre le
# slot suivant.
if [[ -f "$FAILED_FILE" ]]; then
    FAILED_SLUGS=$(sort -u "$FAILED_FILE" | tr '\n' ' ')
    FAILED_COUNT=$(sort -u "$FAILED_FILE" | wc -l | tr -d ' ')
    if [[ -n "${FAILED_SLUGS// /}" ]]; then
        log "════════════════════════════════════════════════"
        log "  Redistribution — $FAILED_COUNT spécialité(s) en erreur : $FAILED_SLUGS"
        log "  Relance en round-robin sur les 4 comptes…"
        run_backlog "$FAILED_SLUGS"
        log "  Redistribution terminée."
    fi
    rm -f "$FAILED_FILE"
fi

log "  Log : $LOGFILE"
log "════════════════════════════════════════════════"

[[ $S1 -eq 0 ]] && [[ $S2 -eq 0 ]] && [[ $S3 -eq 0 ]] && [[ $S4 -eq 0 ]]
