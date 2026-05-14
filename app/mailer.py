# app/mailer.py
"""
Envoi des newsletters par email.

Priorité :
  1. Brevo API (BREVO_API_KEY défini)
  2. SMTP générique (SMTP_HOST défini) — fallback ou dev local

Variables d'environnement :
  BREVO_API_KEY        clé API Brevo (transactionnel)
  MAIL_FROM            expéditeur   (ex: newsletter@med-news.fr)
  MAIL_FROM_NAME       nom affiché  (ex: MedNews)

  # Fallback SMTP
  SMTP_HOST            ex: smtp.gmail.com
  SMTP_PORT            défaut 587
  SMTP_USER
  SMTP_PASSWORD
  SMTP_USE_TLS         true | false (défaut true)
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import NamedTuple

import httpx

MAX_RETRIES = 3
# Retryable HTTP status codes (rate-limit, server errors)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class MailResult(NamedTuple):
    success: bool
    recipient: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Helpers config
# ---------------------------------------------------------------------------

def _from_address() -> tuple[str, str]:
    addr = os.environ.get("MAIL_FROM", "newsletter@med-news.fr")
    name = os.environ.get("MAIL_FROM_NAME", "MedNews")
    return addr, name


# ---------------------------------------------------------------------------
# Envoi via Brevo
# ---------------------------------------------------------------------------

def _send_brevo(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    api_key = "".join(os.environ["BREVO_API_KEY"].split())
    from_addr, from_name = _from_address()

    payload = {
        "sender": {"email": from_addr, "name": from_name},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html,
        "textContent": plain,
    }

    last_error: str = ""
    for attempt in range(MAX_RETRIES):
        try:
            r = httpx.post(
                "https://api.brevo.com/v3/smtp/email",
                json=payload,
                headers={
                    "api-key": api_key,
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
            if r.status_code in (200, 201):
                return MailResult(success=True, recipient=to_email)
            last_error = f"Brevo HTTP {r.status_code}: {r.text[:200]}"
            if r.status_code not in _RETRYABLE_STATUS:
                break
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_error = str(e)
        except Exception as e:
            return MailResult(success=False, recipient=to_email, error=str(e))

        if attempt < MAX_RETRIES - 1:
            delay = 2 ** (attempt + 1)
            logger.warning("Brevo retry %d/%d pour %s dans %ds", attempt + 1, MAX_RETRIES, to_email[:2] + "***", delay)
            time.sleep(delay)

    return MailResult(success=False, recipient=to_email, error=last_error)


# ---------------------------------------------------------------------------
# Envoi via SMTP
# ---------------------------------------------------------------------------

def _send_smtp(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"
    from_addr, from_name = _from_address()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_email
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    last_error: str = ""
    for attempt in range(MAX_RETRIES):
        try:
            ctx = ssl.create_default_context() if use_tls else None
            with smtplib.SMTP(host, port, timeout=30) as s:
                if use_tls:
                    s.ehlo()
                    s.starttls(context=ctx)
                if user:
                    s.login(user, password)
                s.sendmail(from_addr, to_email, msg.as_string())
            return MailResult(success=True, recipient=to_email)
        except (OSError, smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException) as e:
            last_error = str(e)
        except Exception as e:
            return MailResult(success=False, recipient=to_email, error=str(e))

        if attempt < MAX_RETRIES - 1:
            delay = 2 ** (attempt + 1)
            logger.warning("SMTP retry %d/%d pour %s dans %ds", attempt + 1, MAX_RETRIES, to_email[:2] + "***", delay)
            time.sleep(delay)

    return MailResult(success=False, recipient=to_email, error=last_error)


# ---------------------------------------------------------------------------
# Interface publique
# ---------------------------------------------------------------------------

def send_email(
    to_email: str,
    subject: str,
    html: str,
    plain: str,
) -> MailResult:
    """
    Envoie un email. Choisit automatiquement SendGrid ou SMTP.
    """
    if os.environ.get("BREVO_API_KEY"):
        logger.debug("Envoi via Brevo")
        return _send_brevo(to_email, subject, html, plain)

    if os.environ.get("SMTP_HOST"):
        logger.debug("Envoi via SMTP")
        return _send_smtp(to_email, subject, html, plain)

    raise RuntimeError(
        "Aucun transport email configuré. "
        "Définir BREVO_API_KEY ou SMTP_HOST dans l'environnement."
    )


def send_bulk(
    recipients: list[str],
    subject: str,
    html: str,
    plain: str,
) -> dict:
    """
    Envoie à une liste de destinataires. Retourne un rapport.
    """
    ok = []
    errors = []
    for email in recipients:
        result = send_email(email, subject, html, plain)
        if result.success:
            ok.append(email)
        else:
            # On inclut l'email dans errors pour que l'admin puisse investiguer,
            # mais on ne le loggue pas en clair (évite la fuite PII dans les logs)
            errors.append({"email": email, "error": result.error})
            redacted = email[:2] + "***@***" if "@" in email else "***"
            logger.error("Échec envoi %s : %s", redacted, result.error)

    return {"sent": len(ok), "failed": len(errors), "errors": errors}
