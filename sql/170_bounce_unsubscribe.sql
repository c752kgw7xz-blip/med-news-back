-- 170_bounce_unsubscribe.sql
-- Ajoute le suivi des bounces et le mécanisme d'unsubscribe sur la table users.
-- Permet de filtrer les envois pour éviter les hard-bounces répétés et respecter
-- les désabonnements (CAN-SPAM, RGPD).

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_unsubscribed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bounce_status TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bounce_date TIMESTAMPTZ;

-- bounce_status : NULL (ok) | 'temporary' (soft bounce) | 'permanent' (hard bounce)
-- is_unsubscribed : opt-out volontaire de l'utilisateur

COMMENT ON COLUMN users.is_unsubscribed IS 'true si l''utilisateur a demandé le désabonnement';
COMMENT ON COLUMN users.bounce_status IS 'NULL=ok, temporary=soft bounce, permanent=hard bounce';

CREATE INDEX IF NOT EXISTS idx_users_unsubscribed ON users (is_unsubscribed) WHERE is_unsubscribed = true;
CREATE INDEX IF NOT EXISTS idx_users_bounce ON users (bounce_status) WHERE bounce_status IS NOT NULL;
