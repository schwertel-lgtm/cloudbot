"""
Audit-Logging fuer den Cloudbot.
Loggt alle Aktionen im JSON-Lines Format.
"""

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Audit Logger
audit_logger = logging.getLogger("cloudbot.audit")
audit_logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    LOG_DIR / "audit.log",
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding="utf-8",
)
handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(handler)

# Security Logger (unautorisierte Zugriffe)
security_logger = logging.getLogger("cloudbot.security")
security_logger.setLevel(logging.WARNING)

sec_handler = RotatingFileHandler(
    LOG_DIR / "security.log",
    maxBytes=2 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
sec_handler.setFormatter(logging.Formatter("%(message)s"))
security_logger.addHandler(sec_handler)


def log_action(chat_id: int, command: str, args: str, result: str, success: bool):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "chat_id": chat_id,
        "command": command,
        "args": args,
        "result": result[:500],
        "success": success,
    }
    audit_logger.info(json.dumps(entry, ensure_ascii=False))


def log_unauthorized(chat_id: int, username: str, command: str):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "UNAUTHORIZED_ACCESS",
        "chat_id": chat_id,
        "username": username,
        "command": command,
    }
    security_logger.warning(json.dumps(entry, ensure_ascii=False))


def log_blocked_command(chat_id: int, command: str, reason: str):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "BLOCKED_COMMAND",
        "chat_id": chat_id,
        "command": command,
        "reason": reason,
    }
    security_logger.warning(json.dumps(entry, ensure_ascii=False))


def get_recent_logs(count: int = 20) -> str:
    log_file = LOG_DIR / "audit.log"
    if not log_file.exists():
        return "(keine Logs vorhanden)"
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    recent = lines[-count:]
    output = []
    for line in recent:
        try:
            entry = json.loads(line)
            status = "OK" if entry.get("success") else "FAIL"
            output.append(
                f"{entry['timestamp'][:19]} [{status}] /{entry['command']} {entry.get('args', '')}"
            )
        except json.JSONDecodeError:
            continue
    return "\n".join(output) if output else "(keine Logs vorhanden)"
