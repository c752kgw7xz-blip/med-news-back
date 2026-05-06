#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MedNews — Installation du serveur Hetzner CX22 (Ubuntu 24.04)
# À exécuter en tant que root juste après la création du serveur.
#
# Ce script :
#   1. Met à jour le système
#   2. Installe Python 3, Node.js 20, git, Claude Code CLI
#   3. Crée les utilisateurs mednews1 et mednews2
#   4. Clone le repo dans /opt/mednews/
#   5. Configure les logs et logrotate
#   6. Configure le firewall (UFW)
#
# Après ce script, il reste à faire manuellement :
#   A. Copier .env dans /opt/mednews/.env (DATABASE_URL)
#   B. Authentifier Claude Code pour mednews1 et mednews2 (claude login)
#   C. Ajouter la clé SSH de déploiement GitHub Actions
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="https://github.com/c752kgw7xz-blip/med-news-back.git"
REPO_DIR="/opt/mednews"
LOG_DIR="/var/log/mednews"

echo "═══════════════════════════════════════════════"
echo "  MedNews — Setup serveur Hetzner"
echo "═══════════════════════════════════════════════"

# ─── 1. Mise à jour système ──────────────────────────────────────────────────
echo "[1/7] Mise à jour système..."
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q \
    git curl build-essential \
    python3-pip python3-psycopg2 \
    logrotate ufw

# ─── 2. Node.js 20 LTS ──────────────────────────────────────────────────────
echo "[2/7] Installation Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
apt-get install -y -q nodejs
echo "  Node $(node --version) — npm $(npm --version)"

# ─── 3. Claude Code CLI ─────────────────────────────────────────────────────
echo "[3/7] Installation Claude Code CLI..."
npm install -g @anthropic-ai/claude-code --quiet
echo "  claude $(claude --version 2>/dev/null || echo 'installé')"

# ─── 4. Utilisateurs dédiés ─────────────────────────────────────────────────
echo "[4/7] Création des utilisateurs mednews1 et mednews2..."
for user in mednews1 mednews2 mednews3 mednews4; do
    if id "$user" &>/dev/null; then
        echo "  $user existe déjà"
    else
        useradd -m -s /bin/bash "$user"
        echo "  $user créé"
    fi
done

# ─── 5. Clone du repo ────────────────────────────────────────────────────────
echo "[5/7] Clone du repo dans $REPO_DIR..."
if [ -d "$REPO_DIR/.git" ]; then
    echo "  Repo déjà présent — git pull"
    git -C "$REPO_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$REPO_DIR"
fi
chmod +x "$REPO_DIR/scripts/"*.sh

# Dépendances Python
pip3 install -r "$REPO_DIR/requirements.txt" -q

# ─── 6. Logs et logrotate ────────────────────────────────────────────────────
echo "[6/7] Configuration logs..."
mkdir -p "$LOG_DIR"
chmod 1777 "$LOG_DIR"

cat > /etc/logrotate.d/mednews << 'EOF'
/var/log/mednews/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 0644 root root
}
EOF

# ─── 7. Cron triage (3 créneaux tous les 2 jours) ────────────────────────────
echo "[7/8] Configuration cron triage..."

# Même fréquence que la collecte GHA (*/2)
# Slot 1 — 05h UTC = 06h Paris (CET) / 07h Paris (CEST) — après fin de collecte (~05h UTC)
# Slot 2 — 11h UTC = 12h Paris (CET) / 13h Paris (CEST)
# Slot 3 — 17h UTC = 18h Paris (CET) / 19h Paris (CEST)
cat > /etc/cron.d/mednews-triage << 'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Slot 1 — matin (après collecte GHA)
0 5 */2 * * root /opt/mednews/scripts/triage_orchestrator.sh --slot 1 >> /var/log/mednews/cron.log 2>&1

# Slot 2 — midi
0 11 */2 * * root /opt/mednews/scripts/triage_orchestrator.sh --slot 2 >> /var/log/mednews/cron.log 2>&1

# Slot 3 — soir
0 17 */2 * * root /opt/mednews/scripts/triage_orchestrator.sh --slot 3 >> /var/log/mednews/cron.log 2>&1
EOF
chmod 644 /etc/cron.d/mednews-triage
echo "  Cron configuré : slots 1/2/3 à 05h/11h/17h UTC tous les 2 jours"

# ─── 8. Firewall UFW ─────────────────────────────────────────────────────────
echo "[8/8] Configuration firewall..."
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable
echo "  UFW actif — SSH autorisé, tout sortant autorisé (Neon port 5432 OK)"
echo "  Note : triage-trigger.yml GitHub Actions non utilisé (crons locaux suffisent)"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Setup terminé."
echo ""
echo "  Étapes manuelles restantes :"
echo "  A. Créer /opt/mednews/.env avec DATABASE_URL"
echo "  B. su - mednews1 puis : cd /opt/mednews && claude  → albertinmaxence3@gmail.com"
echo "  C. su - mednews2 puis : cd /opt/mednews && claude  → albertinmaxence4@gmail.com"
echo "  D. su - mednews3 puis : cd /opt/mednews && claude  → maxencealbertin@gmail.com"
echo "  E. su - mednews4 puis : cd /opt/mednews && claude  → albertinmaxence@gmail.com"
echo "  F. Ajouter la clé SSH deploy dans /root/.ssh/authorized_keys"
echo "     (voir instructions GitHub Actions)"
echo "═══════════════════════════════════════════════"
