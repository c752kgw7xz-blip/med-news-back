#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MedNews — Orchestrateur de triage automatique
# Exécuté sur le serveur Hetzner, déclenché par GitHub Actions après collecte.
#
# Deux streams parallèles (mednews1 / mednews2), chacun traite 18 spécialités
# séquentiellement. Une spécialité est skippée si elle n'a aucun candidat NEW
# dans ses sources spécifiques (RÈGLE 0 CLAUDE.md).
#
# Usage:
#   ./triage_orchestrator.sh           # run normal
#   ./triage_orchestrator.sh --dry-run # affiche les commandes sans les exécuter
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="/opt/mednews"
LOG_DIR="/var/log/mednews"
DRY_RUN="${1:-}"
PAUSE_BETWEEN_SESSIONS=90  # secondes entre deux sessions claude (rate limit)

# Chargement DATABASE_URL depuis .env (nécessaire pour check_new_for_specialty.py)
# shellcheck disable=SC1091
if [ -f "$REPO_DIR/.env" ]; then
    set -a; source "$REPO_DIR/.env"; set +a
fi

mkdir -p "$LOG_DIR"
chmod 1777 "$LOG_DIR"
LOGFILE="$LOG_DIR/orchestrator_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

# ─── Répartition des 36 spécialités entre les quatre comptes ─────────────────
# 9 spécialités par compte — charge divisée par 4 vs un compte unique

# mednews1 ↔ albertinmaxence3@gmail.com (+ passe globale)
SPECIALTIES_1=(
    anesthesiologie
    biologiste
    cardiologie
    chirurgie-cardiaque
    chirurgie-orthopedique
    chirurgie-pediatrique
    chirurgie-plastique
    chirurgie-thoracique
    chirurgie-vasculaire
)

# mednews2 ↔ albertinmaxence4@gmail.com
SPECIALTIES_2=(
    dermatologie
    endocrinologie
    gastro-enterologie
    geriatrie
    gynecologie
    hematologie
    infectiologie
    infirmiers
    kinesitherapie
)

# mednews3 ↔ maxencealbertin@gmail.com
SPECIALTIES_3=(
    medecine-generale
    medecine-interne
    medecine-physique
    medecine-urgences
    nephrologie
    neurochirurgie
    neurologie
    oncologie
    ophtalmologie
)

# mednews4 ↔ albertinmaxence@gmail.com
SPECIALTIES_4=(
    orl
    pediatrie
    pharmacien
    pneumologie
    psychiatrie
    radiologie
    rhumatologie
    sage-femme
    urologie
)

# ─── Stream : triage séquentiel d'une liste de spécialités ───────────────────
run_stream() {
    local user="$1"
    shift
    local specialties=("$@")
    local done=0 skipped=0 errors=0

    log "[$user] Démarrage — ${#specialties[@]} spécialités"

    for slug in "${specialties[@]}"; do
        # Vérifier candidats NEW spécifiques à cette spécialité
        new_count=$(su - "$user" -c \
            "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py $slug" \
            2>>"$LOGFILE" || echo "0")
        new_count=$(echo "$new_count" | tr -d '[:space:]')

        if [ "${new_count:-0}" -eq 0 ]; then
            log "[$user] SKIP     $slug — 0 candidats NEW"
            ((skipped++))
            continue
        fi

        log "[$user] START    $slug — $new_count candidats NEW"

        if [ "$DRY_RUN" = "--dry-run" ]; then
            log "[$user] DRY-RUN  $slug — claude -p 'lance $slug'"
            ((done++))
        else
            local slug_log="$LOG_DIR/${slug}_$(date +%Y%m%d).log"
            if su - "$user" -c \
                "cd $REPO_DIR && claude -p 'lance $slug'" \
                >> "$slug_log" 2>&1; then
                log "[$user] DONE     $slug"
                ((done++))
            else
                log "[$user] ERROR    $slug — voir $slug_log"
                ((errors++))
            fi
            sleep "$PAUSE_BETWEEN_SESSIONS"
        fi
    done

    log "[$user] Stream terminé — done=$done skipped=$skipped errors=$errors"
}

# ─── Passe 0 : triage global (sources communes) ──────────────────────────────
# Exécutée une seule fois avant les streams parallèles.
# Après cette passe, toutes les candidates "tous" sont LLM_DONE → invisibles
# aux sessions "lance X" qui suivent.

run_global() {
    local user="mednews1"

    local new_count
    new_count=$(su - "$user" -c \
        "cd $REPO_DIR && DATABASE_URL='$DATABASE_URL' python3 scripts/check_new_for_specialty.py global" \
        2>>"$LOGFILE" || echo "0")
    new_count=$(echo "$new_count" | tr -d '[:space:]')

    if [ "${new_count:-0}" -eq 0 ]; then
        log "[global] SKIP — 0 candidates NEW dans les sources communes"
        return 0
    fi

    log "[global] START — $new_count candidates NEW (ANSM, HAS, JORF, EMA, FDA, NEJM…)"

    if [ "$DRY_RUN" = "--dry-run" ]; then
        log "[global] DRY-RUN — claude -p 'triage global'"
    else
        su - "$user" -c \
            "cd $REPO_DIR && claude -p 'triage global'" \
            >> "$LOG_DIR/global_$(date +%Y%m%d).log" 2>&1
    fi

    log "[global] DONE"
    sleep "$PAUSE_BETWEEN_SESSIONS"
}

# ─── Lancement ────────────────────────────────────────────────────────────────
log "════════════════════════════════════════════════"
log "  MedNews triage démarré — $(date '+%Y-%m-%d %H:%M:%S UTC')"
[ "$DRY_RUN" = "--dry-run" ] && log "  MODE DRY-RUN"
log "════════════════════════════════════════════════"

# Passe 0 — global (séquentiel, doit finir avant les spécialités)
run_global
STATUS_GLOBAL=$?

if [ $STATUS_GLOBAL -ne 0 ]; then
    log "[global] ERREUR — les streams spécialités sont lancés quand même"
fi

# Passes 1-4 — spécialités en parallèle (4 streams)
run_stream mednews1 "${SPECIALTIES_1[@]}" &
PID1=$!

run_stream mednews2 "${SPECIALTIES_2[@]}" &
PID2=$!

run_stream mednews3 "${SPECIALTIES_3[@]}" &
PID3=$!

run_stream mednews4 "${SPECIALTIES_4[@]}" &
PID4=$!

wait $PID1; STATUS1=$?
wait $PID2; STATUS2=$?
wait $PID3; STATUS3=$?
wait $PID4; STATUS4=$?

log "════════════════════════════════════════════════"
[ $STATUS_GLOBAL -eq 0 ] && log "  global   : OK" || log "  global   : ERREUR"
[ $STATUS1 -eq 0 ] && log "  mednews1 : OK" || log "  mednews1 : ERREUR (code $STATUS1)"
[ $STATUS2 -eq 0 ] && log "  mednews2 : OK" || log "  mednews2 : ERREUR (code $STATUS2)"
[ $STATUS3 -eq 0 ] && log "  mednews3 : OK" || log "  mednews3 : ERREUR (code $STATUS3)"
[ $STATUS4 -eq 0 ] && log "  mednews4 : OK" || log "  mednews4 : ERREUR (code $STATUS4)"
log "  Log complet : $LOGFILE"
log "════════════════════════════════════════════════"

# Exit 1 si l'un des passages a échoué
[ $STATUS_GLOBAL -eq 0 ] && [ $STATUS1 -eq 0 ] && [ $STATUS2 -eq 0 ] && [ $STATUS3 -eq 0 ] && [ $STATUS4 -eq 0 ]
