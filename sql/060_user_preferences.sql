-- Migration 060 : préférences utilisateur (notifications + newsletter)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS notif_newsletter BOOLEAN DEFAULT true,
  ADD COLUMN IF NOT EXISTS notif_urgent BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS newsletter_frequency VARCHAR(20) DEFAULT 'monthly';
