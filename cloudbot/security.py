"""
Zentrales Sicherheitsmodul fuer den Cloudbot.
Alle Validierungen und Sicherheitsregeln an einem Ort.
"""

import os
import re

ALLOWED_CHAT_ID = int(os.environ["TELEGRAM_CHAT_ID"])

# Whitelist erlaubter Container-Namen
ALLOWED_CONTAINERS = {"kali", "cloudbot", "nordvpn"}

# Maximale Befehlslaenge
MAX_COMMAND_LENGTH = 500

# Blocklist fuer exec-Befehle (Regex-Patterns)
BLOCKED_COMMANDS = [
    # Dateisystem zerstoeren
    r"\brm\s+(-[rRf]+\s+)?/",
    r"\bmkfs\b",
    r"\bdd\s+.*of=/dev/",
    r">\s*/dev/sd",

    # Remote Code Execution / Reverse Shells
    r"\bcurl\b.*\|\s*(ba)?sh",
    r"\bwget\b.*\|\s*(ba)?sh",
    r"\bnc\s+.*-[elp]",
    r"\b(bash|sh)\s+-i",
    r"\bpython[23]?\b.*\bsocket\b",
    r"\bperl\b.*\bsocket\b",
    r"\bphp\b.*\bfsockopen\b",
    r"\bruby\b.*\bTCPSocket\b",
    r"\bsocat\b",
    r"\b/dev/tcp/",

    # Privilege Escalation / User Manipulation
    r"\bchmod\s+[0-7]*777",
    r"\b(passwd|useradd|usermod|groupmod)\b",
    r"/etc/(passwd|shadow|sudoers)",
    r"\bsudo\b",
    r"\bsu\s+-?\s",

    # System-Manipulation
    r"\biptables\b",
    r"\bdocker\b",
    r"\bmount\b",
    r"\bumount\b",
    r"\bsystemctl\b",
    r"\bservice\s+",
    r"\binit\s+",
    r"\bshutdown\b",
    r"\breboot\b",

    # Code-Injection
    r"\beval\b",
    r"\bexec\b.*\(",
    r"`.*`",

    # Crypto-Mining
    r"\bxmrig\b",
    r"\bminerd\b",
    r"\bcpuminer\b",

    # Daten-Exfiltration
    r"\bcurl\b.*-[dX].*POST",
    r"\bwget\b.*--post",
    r"\bncat\b",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE) for p in BLOCKED_COMMANDS]


def is_authorized(chat_id: int) -> bool:
    return chat_id == ALLOWED_CHAT_ID


def validate_container_name(name: str) -> tuple[bool, str]:
    if not name:
        return False, "Kein Container-Name angegeben."
    if name not in ALLOWED_CONTAINERS:
        allowed = ", ".join(sorted(ALLOWED_CONTAINERS))
        return False, f"Container '{name}' nicht erlaubt. Erlaubt: {allowed}"
    return True, ""


def validate_exec_command(command: str) -> tuple[bool, str]:
    if not command:
        return False, "Kein Befehl angegeben."

    if len(command) > MAX_COMMAND_LENGTH:
        return False, f"Befehl zu lang (max. {MAX_COMMAND_LENGTH} Zeichen)."

    for pattern in _compiled_patterns:
        if pattern.search(command):
            return False, f"Befehl blockiert (Sicherheitsregel: {pattern.pattern})."

    return True, ""


def sanitize_output(text: str) -> str:
    """Entfernt sensible Daten aus der Ausgabe bevor sie an Telegram gesendet wird."""
    # Telegram Bot Tokens
    text = re.sub(r"\b\d+:[A-Za-z0-9_-]{35,}\b", "[TOKEN ENTFERNT]", text)
    # Passwoerter in Umgebungsvariablen
    text = re.sub(r"(?i)(password|passwd|secret|token|key)\s*[=:]\s*\S+", r"\1=[ENTFERNT]", text)
    return text
