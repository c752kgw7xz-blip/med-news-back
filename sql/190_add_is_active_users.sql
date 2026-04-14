-- 190_add_is_active_users.sql
-- Ajoute la colonne is_active sur la table users.
-- Permet à l'admin de désactiver un compte médecin sans le supprimer.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
