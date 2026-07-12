"""Credential-free command policy shared by controller and Docker broker."""

import re

MAX_COMMAND_LENGTH = 2000
ALLOWED_CONTAINERS = frozenset({"kali", "cloudbot", "nordvpn"})

BLOCKED_COMMANDS = [
    r"\brm\s+(-[rRf]+\s+)?/", r"\bmkfs\b", r"\bdd\s+.*of=/dev/", r">\s*/dev/sd",
    r"\bcurl\b.*\|\s*(ba)?sh", r"\bwget\b.*\|\s*(ba)?sh", r"\bnc\s+.*-[elp]",
    r"\b(bash|sh)\s+-i", r"\bpython[23]?\b.*\bsocket\b", r"\bperl\b.*\bsocket\b",
    r"\bphp\b.*\bfsockopen\b", r"\bruby\b.*\bTCPSocket\b", r"\bsocat\b", r"\b/dev/tcp/",
    r"\bchmod\s+[0-7]*777", r"\b(passwd|useradd|usermod|groupmod)\b",
    r"/etc/(passwd|shadow|sudoers)", r"\bsudo\b", r"\bsu\s+-?\s",
    r"\biptables\b", r"\bdocker\b", r"\bmount\b", r"\bumount\b", r"\bsystemctl\b",
    r"\bservice\s+", r"\binit\s+", r"\bshutdown\b", r"\breboot\b",
    r"\beval\b", r"\bexec\b.*\(", r"`.*`", r"\bperl\b.*\b(system|exec)\s*\(",
    r"\bruby\b.*\b(system|exec|spawn)\s*\(",
    r"\bpython[23]?\b.*\b(os\.system|subprocess|os\.exec)",
    r"\bphp\b.*\b(system|exec|passthru|shell_exec)\s*\(", r"\blua\b.*\bos\.execute\b",
    r"\bxmrig\b", r"\bminerd\b", r"\bcpuminer\b",
    r"\bcurl\b.*-[dX].*POST", r"\bwget\b.*--post", r"\bncat\b",
]

_COMPILED_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in BLOCKED_COMMANDS)


def validate_exec_command(command: str) -> tuple[bool, str]:
    if not command:
        return False, "Kein Befehl angegeben."
    if len(command) > MAX_COMMAND_LENGTH:
        return False, f"Befehl zu lang (max. {MAX_COMMAND_LENGTH} Zeichen)."
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(command):
            return False, f"Befehl blockiert (Sicherheitsregel: {pattern.pattern})."
    return True, ""
