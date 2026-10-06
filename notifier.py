"""
ARGUS notifier.

Pushes new alerts to the operator through Telegram, email (SMTP),
and an optional generic webhook. Uses only the standard library.

Configuration is read from environment variables, or from a local
.env file in the project root. Nothing is sent unless a channel is
configured, and a failed notification never stops a scan.

    ARGUS_NOTIFY_MIN_SEVERITY   informational | low | medium | high | critical
                                (default: informational, so every new alert pings)
    ARGUS_TELEGRAM_TOKEN        bot token from @BotFather
    ARGUS_TELEGRAM_CHAT_ID      chat or channel id to post to
    ARGUS_SMTP_HOST             e.g. smtp.gmail.com
    ARGUS_SMTP_PORT             default 587 (STARTTLS)
    ARGUS_SMTP_USER
    ARGUS_SMTP_PASSWORD         use an app password
    ARGUS_EMAIL_TO              comma separated recipients
    ARGUS_EMAIL_FROM            defaults to ARGUS_SMTP_USER
    ARGUS_WEBHOOK_URL           receives the alert as JSON (POST)
"""

import json
import os
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from core.database import get_connection


SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_env_loaded = False


def _load_env_file():
    """Load KEY=VALUE lines from .env without overriding real env vars."""
    global _env_loaded

    if _env_loaded:
        return

    _env_loaded = True

    path = Path(".env")

    if not path.exists():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(
            key.strip(),
            value.strip().strip('"').strip("'"),
        )


def _get(name, default=""):
    _load_env_file()
    return os.environ.get(name, default).strip()


def telegram_configured():
    return bool(_get("ARGUS_TELEGRAM_TOKEN") and _get("ARGUS_TELEGRAM_CHAT_ID"))


def email_configured():
    return bool(
        _get("ARGUS_SMTP_HOST")
        and _get("ARGUS_SMTP_USER")
        and _get("ARGUS_SMTP_PASSWORD")
        and _get("ARGUS_EMAIL_TO")
    )


def webhook_configured():
    return bool(_get("ARGUS_WEBHOOK_URL"))


def configured_channels():
    """Names of the channels that are ready to send."""
    channels = []

    if telegram_configured():
        channels.append("telegram")

    if email_configured():
        channels.append("email")

    if webhook_configured():
        channels.append("webhook")

    return channels


def meets_threshold(severity):
    minimum = _get("ARGUS_NOTIFY_MIN_SEVERITY", "informational").lower()

    return (
        SEVERITY_ORDER.get((severity or "").lower(), 0)
        >= SEVERITY_ORDER.get(minimum, 0)
    )


def get_alert_summary(alert_id):
    """Collect what the message needs about one alert."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                alerts.id,
                alerts.event_type,
                alerts.severity,
                alerts.port,
                alerts.protocol,
                alerts.first_seen,
                assets.ip,
                assets.hostname,
                events.message
            FROM alerts
            JOIN assets ON assets.id = alerts.asset_id
            LEFT JOIN events
                ON events.observation_id = alerts.first_observation_id
               AND events.asset_id = alerts.asset_id
               AND events.event_type = alerts.event_type
               AND events.port IS alerts.port
            WHERE alerts.id = ?
            LIMIT 1
            """,
            (alert_id,),
        ).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


def build_message(summary):
    kind = summary["event_type"].replace("_", " ").title()
    severity = summary["severity"].upper()

    target = summary["ip"]

    if summary.get("hostname"):
        target += f" ({summary['hostname']})"

    lines = [
        f"ARGUS alert #{summary['id']}: {kind}",
        f"Severity: {severity}",
        f"Asset: {target}",
    ]

    if summary.get("port"):
        lines.append(f"Port: {summary['port']}/{summary['protocol']}")

    if summary.get("message"):
        lines.append("")
        lines.append(summary["message"])

    base_url = _get("ARGUS_DASHBOARD_URL", "http://127.0.0.1:5000")
    lines.append("")
    lines.append(f"{base_url}/alert/{summary['id']}")

    return "\n".join(lines)


def send_telegram(text):
    token = _get("ARGUS_TELEGRAM_TOKEN")
    payload = json.dumps(
        {
            "chat_id": _get("ARGUS_TELEGRAM_CHAT_ID"),
            "text": text,
            "disable_web_page_preview": True,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=10):
        pass


def send_email(subject, text):
    message = EmailMessage()
    sender = _get("ARGUS_EMAIL_FROM") or _get("ARGUS_SMTP_USER")

    message["Subject"] = subject
    message["From"] = sender
    message["To"] = _get("ARGUS_EMAIL_TO")
    message.set_content(text)

    port = int(_get("ARGUS_SMTP_PORT", "587"))

    with smtplib.SMTP(_get("ARGUS_SMTP_HOST"), port, timeout=15) as server:
        server.starttls()
        server.login(_get("ARGUS_SMTP_USER"), _get("ARGUS_SMTP_PASSWORD"))
        server.send_message(message)


def send_webhook(summary, text):
    payload = json.dumps({**summary, "text": text}).encode("utf-8")

    request = urllib.request.Request(
        _get("ARGUS_WEBHOOK_URL"),
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=10):
        pass


def dispatch(summary, text, subject):
    """Send through every configured channel. Returns {channel: error or None}."""
    results = {}

    senders = {
        "telegram": lambda: send_telegram(text),
        "email": lambda: send_email(subject, text),
        "webhook": lambda: send_webhook(summary, text),
    }

    for channel in configured_channels():
        try:
            senders[channel]()
            results[channel] = None

        except (OSError, smtplib.SMTPException, urllib.error.URLError, ValueError) as error:
            results[channel] = str(error)

    return results


def notify_alert(alert_id):
    """
    Notify the operator about a newly created alert.

    Safe to call from the detection flow: it never raises.
    """
    try:
        if not configured_channels():
            return {}

        summary = get_alert_summary(alert_id)

        if summary is None or not meets_threshold(summary["severity"]):
            return {}

        kind = summary["event_type"].replace("_", " ").title()
        subject = f"[ARGUS] {summary['severity'].upper()}: {kind} on {summary['ip']}"

        results = dispatch(summary, build_message(summary), subject)

        for channel, error in results.items():
            if error:
                print(f"[!] ARGUS notify via {channel} failed: {error}")
            else:
                print(f"[+] ARGUS notified via {channel} for alert #{alert_id}")

        return results

    except Exception as error:
        print(f"[!] ARGUS notifier error: {error}")
        return {}


def send_test():
    """Send a test message to every configured channel."""
    channels = configured_channels()

    if not channels:
        print("No notification channel is configured. See core/notifier.py.")
        return

    text = "ARGUS test notification. If you can read this, alerts will reach you."
    results = dispatch({"test": True}, text, "[ARGUS] Test notification")

    for channel, error in results.items():
        print(f"{channel}: {'sent' if error is None else 'failed: ' + error}")


if __name__ == "__main__":
    send_test()
