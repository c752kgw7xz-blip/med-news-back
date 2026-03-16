#!/usr/bin/env python3
"""Reset admin credentials (email + password) — one-shot script.

Usage:
    python3 scripts/reset_admin.py <email> [<password>]
    python3 scripts/reset_admin.py admin@example.com
"""

import getpass
import hashlib
import os
import sys

from dotenv import load_dotenv

# ── Load env ──────────────────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("✗ DATABASE_URL manquant dans .env")
    sys.exit(1)

# ── Email from CLI arg ─────────────────────────────────────────
if len(sys.argv) < 2:
    print("Usage: python3 scripts/reset_admin.py <email> [<password>]")
    sys.exit(1)

NEW_EMAIL = sys.argv[1].strip().lower()
if "@" not in NEW_EMAIL:
    print(f"✗ Email invalide : {NEW_EMAIL}")
    sys.exit(1)

# ── Password input ────────────────────────────────────────────
if len(sys.argv) > 2:
    password = sys.argv[2]
else:
    try:
        password = getpass.getpass("Nouveau mot de passe admin : ")
    except EOFError:
        print("✗ Impossible de lire le mot de passe (utilisez: python3 reset_admin.py <email> <password>)")
        sys.exit(1)

if len(password) < 8:
    print("✗ Le mot de passe doit faire au moins 8 caractères")
    sys.exit(1)

# ── Import security helpers ────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.security import hash_password, encrypt_email  # noqa: E402

email_norm = NEW_EMAIL
email_lookup = hashlib.sha256(email_norm.encode("utf-8")).digest()
email_ciphertext = encrypt_email(email_norm)
password_hash = hash_password(password)

# ── Update DB ─────────────────────────────────────────────────
import psycopg  # noqa: E402

conn = psycopg.connect(DATABASE_URL)
try:
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE users
               SET email_ciphertext = %s,
                   email_lookup     = %s,
                   password_hash    = %s
             WHERE is_admin = true;""",
            (email_ciphertext, email_lookup, password_hash),
        )
        count = cur.rowcount
    conn.commit()
finally:
    conn.close()

if count:
    print(f"✓ Admin mis à jour ({count} compte(s)) — email: {NEW_EMAIL}")
else:
    print("✗ Aucun compte admin trouvé (is_admin = true)")
    sys.exit(1)
