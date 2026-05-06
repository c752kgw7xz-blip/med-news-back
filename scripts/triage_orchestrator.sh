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
            if su - "$user" -c "cd $REPO_DIR && claude -p 'lance $slug'" \
                >> "$slug_log" 2>&1; then
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
        su - "$user" -c "cd $REPO_DIR && claude -p 'triage global'" \
            >> "$LOG_DIR/global_$(date +%Y%m%d).log" 2>&1
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
if [[ "$SLOT" == "1" ]]; then
    run_global
fi

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
