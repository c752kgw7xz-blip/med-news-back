# app/billing_routes.py
"""Routes facturation Stripe — abonnement mensuel."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.db import get_conn
from app.portal_routes import _get_current_user_id
from app.security import decrypt_email, verify_signup_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])

STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID       = os.environ.get("STRIPE_PRICE_ID", "")
BASE_URL              = os.environ.get("BASE_URL", "http://localhost:8000")

stripe.api_key = STRIPE_SECRET_KEY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user_row(user_id: str) -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, email_ciphertext, trial_ends_at, subscribed_until,
                       stripe_customer_id, stripe_subscription_id, plan
                FROM users WHERE id = %s
            """, (user_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {
        "id": str(row[0]),
        "email": decrypt_email(row[1]),
        "trial_ends_at": row[2],
        "subscribed_until": row[3],
        "stripe_customer_id": row[4],
        "stripe_subscription_id": row[5],
        "plan": row[6] or "standard",
    }


BETA_END = datetime(2026, 8, 1, tzinfo=timezone.utc)  # Accès gratuit jusqu'au lancement officiel


def _has_active_access(user: dict) -> bool:
    now = datetime.now(timezone.utc)
    beta_ok    = now < BETA_END
    trial_ok   = user["trial_ends_at"] and user["trial_ends_at"] > now
    sub_ok     = user["subscribed_until"] and user["subscribed_until"] > now
    student_ok = user.get("plan") == "student"
    return bool(beta_ok or trial_ok or sub_ok or student_ok)


def _days_left(user: dict) -> int:
    now = datetime.now(timezone.utc)
    candidates = [BETA_END]  # minimum garanti jusqu'au 1er août
    if user["trial_ends_at"] and user["trial_ends_at"] > now:
        candidates.append(user["trial_ends_at"])
    if user["subscribed_until"] and user["subscribed_until"] > now:
        candidates.append(user["subscribed_until"])
    best = max(candidates)
    return max(0, (best - now).days)


def _ensure_stripe_customer(user: dict) -> str:
    """Crée ou récupère le customer Stripe, met à jour la DB si créé."""
    if user["stripe_customer_id"]:
        return user["stripe_customer_id"]
    customer = stripe.Customer.create(
        email=user["email"],
        metadata={"user_id": user["id"]},
    )
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET stripe_customer_id = %s WHERE id = %s",
                (customer.id, user["id"]),
            )
    return customer.id


# ---------------------------------------------------------------------------
# GET /billing/status
# ---------------------------------------------------------------------------

@router.get("/status")
def billing_status(user_id: str = Depends(_get_current_user_id)):
    user = _get_user_row(user_id)
    now = datetime.now(timezone.utc)
    is_trial = bool(user["trial_ends_at"] and user["trial_ends_at"] > now
                    and not (user["subscribed_until"] and user["subscribed_until"] > now))
    is_student = user.get("plan") == "student"

    # Demande étudiante en attente de validation
    student_pending = False
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM student_requests WHERE user_id = %s AND status = 'pending' LIMIT 1",
                (user_id,),
            )
            student_pending = cur.fetchone() is not None

    now = datetime.now(timezone.utc)
    return {
        "access": _has_active_access(user),
        "is_beta": now < BETA_END,
        "beta_ends_at": BETA_END.isoformat(),
        "is_trial": is_trial,
        "is_student": is_student,
        "student_pending": student_pending,
        "days_left": _days_left(user),
        "trial_ends_at":    user["trial_ends_at"].isoformat() if user["trial_ends_at"] else None,
        "subscribed_until": user["subscribed_until"].isoformat() if user["subscribed_until"] else None,
        "has_subscription": bool(user["stripe_subscription_id"]),
    }


# ---------------------------------------------------------------------------
# POST /billing/checkout  — crée une session Stripe Checkout
# ---------------------------------------------------------------------------

class CheckoutRequest(BaseModel):
    success_url: str | None = None
    cancel_url:  str | None = None


@router.post("/checkout")
def create_checkout(
    payload: CheckoutRequest,
    user_id: str = Depends(_get_current_user_id),
):
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        raise HTTPException(status_code=503, detail="billing not configured")

    user = _get_user_row(user_id)
    customer_id = _ensure_stripe_customer(user)

    success_url = payload.success_url or f"{BASE_URL}/portal?subscribed=1"
    cancel_url  = payload.cancel_url  or f"{BASE_URL}/portal"

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        mode="subscription",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"user_id": user_id},
    )
    return {"checkout_url": session.url}


# ---------------------------------------------------------------------------
# POST /billing/checkout-signup  — Stripe Checkout lors de l'inscription (sans JWT)
# ---------------------------------------------------------------------------

class CheckoutSignupRequest(BaseModel):
    user_id: str
    signup_token: str
    success_url: str | None = None
    cancel_url:  str | None = None


@router.post("/checkout-signup")
def create_checkout_signup(payload: CheckoutSignupRequest):
    """Crée une session Stripe Checkout pour un nouvel inscrit (sans JWT).
    Utilise trial_period_days=30 — l'utilisateur entre sa carte mais n'est pas débité pendant 30 jours.
    """
    if not verify_signup_token(payload.signup_token, payload.user_id):
        raise HTTPException(status_code=403, detail="invalid or expired signup token")
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        raise HTTPException(status_code=503, detail="billing not configured")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email_ciphertext, stripe_customer_id FROM users WHERE id = %s",
                (payload.user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    user = {
        "id": str(row[0]),
        "email": decrypt_email(row[1]),
        "stripe_customer_id": row[2],
        "trial_ends_at": None,
        "subscribed_until": None,
        "stripe_subscription_id": None,
        "plan": "standard",
    }
    customer_id = _ensure_stripe_customer(user)

    success_url = payload.success_url or f"{BASE_URL}/signup?done=1&subscribed=1"
    cancel_url  = payload.cancel_url  or f"{BASE_URL}/signup?done=1"

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        mode="subscription",
        subscription_data={"trial_period_days": 30},
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"user_id": payload.user_id},
    )
    return {"checkout_url": session.url}


# ---------------------------------------------------------------------------
# POST /billing/customer-portal  — Stripe Customer Portal (gérer/résilier)
# ---------------------------------------------------------------------------

@router.post("/customer-portal")
def customer_portal(user_id: str = Depends(_get_current_user_id)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="billing not configured")

    user = _get_user_row(user_id)
    if not user["stripe_customer_id"]:
        raise HTTPException(status_code=400, detail="no stripe customer")

    session = stripe.billing_portal.Session.create(
        customer=user["stripe_customer_id"],
        return_url=f"{BASE_URL}/portal",
    )
    return {"portal_url": session.url}


# ---------------------------------------------------------------------------
# POST /billing/webhook  — events Stripe
# ---------------------------------------------------------------------------

@router.post("/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="webhook not configured")

    body      = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(body, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="invalid signature")

    etype = event["type"]
    data  = event["data"]["object"]

    if etype in ("checkout.session.completed",):
        sub_id      = data.get("subscription")
        customer_id = data.get("customer")
        user_id     = data.get("metadata", {}).get("user_id")
        if sub_id and customer_id and user_id:
            sub = stripe.Subscription.retrieve(sub_id)
            period_end = datetime.fromtimestamp(sub["current_period_end"], tz=timezone.utc)
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE users
                        SET subscribed_until = %s,
                            stripe_customer_id = %s,
                            stripe_subscription_id = %s
                        WHERE id = %s
                    """, (period_end, customer_id, sub_id, user_id))
            logger.info("Checkout completed — user %s subscribed until %s", user_id, period_end)

    elif etype == "invoice.paid":
        sub_id      = data.get("subscription")
        customer_id = data.get("customer")
        if sub_id:
            sub = stripe.Subscription.retrieve(sub_id)
            period_end = datetime.fromtimestamp(sub["current_period_end"], tz=timezone.utc)
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE users SET subscribed_until = %s
                        WHERE stripe_subscription_id = %s
                    """, (period_end, sub_id))
            logger.info("Invoice paid — sub %s renewed until %s", sub_id, period_end)

    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub_id = data.get("id")
        if sub_id:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE users SET subscribed_until = NOW(), stripe_subscription_id = NULL
                        WHERE stripe_subscription_id = %s
                    """, (sub_id,))
            logger.info("Subscription cancelled — sub %s", sub_id)

    return {"received": True}
