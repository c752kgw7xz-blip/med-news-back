# app/push_service.py
"""
Envoi de push notifications via Firebase Cloud Messaging (FCM v1).

Prérequis :
  pip install firebase-admin
  Env var FIREBASE_CREDENTIALS = contenu JSON du service account Firebase
           (ou chemin vers le fichier si commence par '/')
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_firebase_app = None


def _get_app():
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    creds_env = os.environ.get("FIREBASE_CREDENTIALS")
    if not creds_env:
        logger.warning("FIREBASE_CREDENTIALS non définie — push notifications désactivées")
        return None

    try:
        import firebase_admin
        from firebase_admin import credentials

        if creds_env.startswith("/"):
            cred = credentials.Certificate(creds_env)
        else:
            cred = credentials.Certificate(json.loads(creds_env))

        _firebase_app = firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialisé")
        return _firebase_app
    except Exception as e:
        logger.error("Erreur init Firebase : %s", e)
        return None


def send_push_to_tokens(
    tokens: list[str],
    title: str,
    body: str,
    data: Optional[dict] = None,
) -> tuple[int, list[str]]:
    """Envoie une notification à une liste de tokens FCM.
    Retourne (nb_succès, tokens_invalides_à_supprimer)."""
    if not tokens:
        return 0, []

    app = _get_app()
    if app is None:
        return 0, []

    try:
        from firebase_admin import messaging

        messages = [
            messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data={k: str(v) for k, v in (data or {}).items()},
                token=token,
            )
            for token in tokens
        ]

        response = messaging.send_each(messages, app=app)
        success = response.success_count
        dead_tokens: list[str] = []

        if response.failure_count:
            for i, resp in enumerate(response.responses):
                if not resp.success:
                    err = str(resp.exception)
                    logger.warning("Push échec token[%d] : %s", i, err)
                    # Supprimer les tokens définitivement invalides
                    if any(k in err for k in (
                        "UNREGISTERED", "registration-token-not-registered",
                        "BadEnvironmentKeyInToken", "BadDeviceToken",
                        "Unregistered", "invalid-registration-token",
                    )):
                        dead_tokens.append(tokens[i])
                        logger.info("Token mort marqué pour suppression : %s…", tokens[i][:20])
            logger.warning(
                "Push partiel : %d succès / %d échecs",
                success,
                response.failure_count,
            )
        return success, dead_tokens
    except Exception as e:
        logger.error("Erreur envoi push : %s", e)
        return 0, []


def notify_specialty_approved(specialty_slug: str, titre: str, item_id: str = "") -> None:
    """
    Envoie une push à tous les médecins de la spécialité quand un article
    est approuvé. Appelé de manière asynchrone (fire-and-forget).
    """
    from app.db import get_conn

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT pt.token
                    FROM push_tokens pt
                    JOIN users u ON u.id = pt.user_id
                    WHERE u.specialty_id = %s
                      AND u.is_active = TRUE
                      AND (u.subscribed_until IS NULL OR u.subscribed_until > now()
                           OR u.trial_ends_at > now())
                    """,
                    (specialty_slug,),
                )
                tokens = [r[0] for r in cur.fetchall()]

        if not tokens:
            return

        data: dict = {"specialty_slug": specialty_slug, "type": "new_article"}
        if item_id:
            data["item_id"] = item_id
        success, dead_tokens = send_push_to_tokens(
            tokens=tokens,
            title="Nouveau dans MedNews",
            body=titre,
            data=data,
        )
        logger.info(
            "Push envoyée à %d appareils pour %s : %s",
            len(tokens),
            specialty_slug,
            titre,
        )

        # Nettoyage automatique des tokens invalides
        if dead_tokens:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM push_tokens WHERE token = ANY(%s)",
                        (dead_tokens,),
                    )
                    conn.commit()
            logger.info("Supprimé %d token(s) mort(s)", len(dead_tokens))
    except Exception as e:
        logger.error("notify_specialty_approved error : %s", e)
