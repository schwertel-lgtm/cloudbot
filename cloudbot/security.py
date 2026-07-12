"""
Zentrales Sicherheitsmodul fuer den Cloudbot.
Alle Validierungen und Sicherheitsregeln an einem Ort.
"""

import os
import re
import time
from collections import defaultdict
from exec_security import ALLOWED_CONTAINERS, BLOCKED_COMMANDS, MAX_COMMAND_LENGTH, validate_exec_command

ALLOWED_CHAT_ID = int(os.environ["TELEGRAM_CHAT_ID"])

# Rate-Limiting: max Nachrichten pro Zeitfenster
RATE_LIMIT_MAX = 10          # max 10 Nachrichten
RATE_LIMIT_WINDOW = 60       # pro 60 Sekunden
_rate_limiter = defaultdict(list)

def is_authorized(chat_id: int) -> bool:
    return chat_id == ALLOWED_CHAT_ID


def check_rate_limit(chat_id: int) -> tuple[bool, str]:
    """Prueft ob die Chat-ID das Rate-Limit ueberschreitet.
    Gibt (True, '') zurueck wenn ok, (False, Meldung) wenn Limit erreicht."""
    now = time.time()
    timestamps = _rate_limiter[chat_id]
    # Alte Eintraege entfernen
    _rate_limiter[chat_id] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limiter[chat_id]) >= RATE_LIMIT_MAX:
        return False, f"Rate-Limit erreicht ({RATE_LIMIT_MAX} Nachrichten pro {RATE_LIMIT_WINDOW}s). Bitte warten."
    _rate_limiter[chat_id].append(now)
    return True, ""


def validate_container_name(name: str) -> tuple[bool, str]:
    if not name:
        return False, "Kein Container-Name angegeben."
    if name not in ALLOWED_CONTAINERS:
        allowed = ", ".join(sorted(ALLOWED_CONTAINERS))
        return False, f"Container '{name}' nicht erlaubt. Erlaubt: {allowed}"
    return True, ""


def sanitize_output(text: str) -> str:
    """Entfernt sensible Daten aus der Ausgabe bevor sie an Telegram gesendet wird."""
    # Telegram Bot Tokens
    text = re.sub(r"\b\d+:[A-Za-z0-9_-]{35,}\b", "[TOKEN ENTFERNT]", text)
    # Passwoerter in Umgebungsvariablen
    text = re.sub(r"(?i)(password|passwd|secret|token|key)\s*[=:]\s*(?!\[ENTFERNT\])\S+", r"\1=[ENTFERNT]", text)
    return text
