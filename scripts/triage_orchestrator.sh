#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MedNews — Orchestrateur de triage automatique
#
# 3 créneaux par jour de collecte, toutes les 48h :
#   Slot 1 — 06h Paris : triage global + spécialités 1-12  (4 comptes × 3 spés)
#   Slot 2 — 12h Paris : spécialités 13-24                 (4 comptes × 3 spés)
#   Slot 3 — 18h Paris : spécialités 25-36                 (4 comptes × 3 spés)
#
# ~6h de gap entre créneaux → rate limits Pro régénérés entre chaque slot.
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

# ─── Stream : triage séquentiel d'une liste de spécialités ───────────────────
run_stream() {
    local user="$1"
    local specialties_str="$2"
    read -ra specialties <<< "$specialties_str"
    local done=0 skipped=0 errors=0

    log "[$user] Slot $SLOT — ${#specialties[@]} spécialités : ${specialties[*]}"

    for slug in "${specialties[@]}"; do
        local new_count
        new_count=$(su - "$user" -c \
            "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py $slug" \
            2>>"$LOGFILE" || echo "0")
        new_count=$(echo "$new_count" | tr -d '[:space:]')

        if [[ "${new_count:-0}" -eq 0 ]]; then
            log "[$user] SKIP     $slug — 0 candidats NEW"
            ((skipped++)) || true
            continue
        fi

        log "[$user] START    $slug — $new_count candidats NEW"

        if [[ -n "$DRY_RUN" ]]; then
            log "[$user] DRY-RUN  $slug"
            ((done++)) || true
        else
            local slug_log="$LOG_DIR/${slug}_$(date +%Y%m%d).log"
            su - "$user" -c "cd $REPO_DIR && claude -p 'lance $slug' --dangerously-skip-permissions --output-format text --permission-prompt-tool stdio" \
                < /dev/null >> "$slug_log" 2>&1 &
            wait $!
            if [[ $? -eq 0 ]]; then
                log "[$user] DONE     $slug"
                ((done++)) || true
            else
                log "[$user] ERROR    $slug — voir $slug_log"
                ((errors++)) || true
            fi
            sleep "$PAUSE_BETWEEN_SESSIONS"
        fi
    done

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

        local cnt
        cnt=$(su - "mednews1" -c \
            "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py $slug" \
            2>>"$LOGFILE" || echo "0")
        cnt=$(echo "$cnt" | tr -d '[:space:]')
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
log "  Log : $LOGFILE"
log "════════════════════════════════════════════════"

[[ $S1 -eq 0 ]] && [[ $S2 -eq 0 ]] && [[ $S3 -eq 0 ]] && [[ $S4 -eq 0 ]]
