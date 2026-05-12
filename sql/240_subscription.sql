-- 240_subscription.sql
-- Colonnes abonnement Stripe sur users.
-- trial_ends_at  : fin de la période d'essai gratuit
-- subscribed_until : fin de l'abonnement payant en cours
-- stripe_customer_id / stripe_subscription_id : IDs Stripe

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS trial_ends_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS subscribed_until   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
  ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;

-- Tous les users existants : accès gratuit jusqu'au 1er août 2026
UPDATE users
SET trial_ends_at = '2026-08-01 00:00:00+00'
WHERE trial_ends_at IS NULL;
