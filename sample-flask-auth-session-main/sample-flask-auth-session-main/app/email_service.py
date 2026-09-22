"""Minimal SMTP delivery. Email is optional in local development."""

import smtplib
from email.message import EmailMessage

from decouple import config


def configure_email(app):
    app.config["MAIL_SERVER"] = config("MAIL_SERVER", default="smtp.gmail.com")
    app.config["MAIL_PORT"] = config("MAIL_PORT", default=587, cast=int)
    app.config["MAIL_USERNAME"] = config("ADMIN_EMAIL", default="")
    app.config["MAIL_PASSWORD"] = config("ADMIN_SMTP_PASSWORD", default="")
    placeholders = {"your-email@gmail.com", "your-app-password", "your-16-character-app-password", "demo test demo test"}
    app.config["MAIL_ENABLED"] = bool(
        app.config["MAIL_USERNAME"]
        and app.config["MAIL_PASSWORD"]
        and app.config["MAIL_USERNAME"] not in placeholders
        and app.config["MAIL_PASSWORD"] not in placeholders
    )


def _send(subject, recipient, body):
    from flask import current_app

    if not current_app.config["MAIL_ENABLED"]:
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = current_app.config["MAIL_USERNAME"]
    message["To"] = recipient
    message.set_content(body)
    try:
        with smtplib.SMTP(current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"], timeout=10) as server:
            server.starttls()
            server.login(current_app.config["MAIL_USERNAME"], current_app.config["MAIL_PASSWORD"])
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        return False


def send_password_reset_email(recipient, code):
    return _send(
        "Password reset verification code",
        recipient,
        f"Your password reset verification code is {code}. It expires in 10 minutes. If you did not request it, ignore this email.",
    )


def send_admin_alert(ip_address, attempt_times):
    from flask import current_app

    return _send(
        "Security alert: failed login attempts",
        current_app.config["MAIL_USERNAME"],
        f"{len(attempt_times)} failed login attempts were recorded from {ip_address}.",
    )
