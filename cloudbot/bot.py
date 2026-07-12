import os
import io
import json
import re
import socket
import asyncio
import logging
import urllib.request
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from telegram import Update, WebAppInfo, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# === Logging-Setup mit Token-Schutz ===
# Hintergrund: Bis 2026-04-21 wurde der Telegram-Bot-Token im Klartext in
# den Container-Logs sichtbar, weil httpx (transitiv via PTB) jeden
# Request inkl. URL auf INFO-Level loggt — und Telegram-API-URLs
# enthalten den Token im Pfad.
#
# Zwei Verteidigungslinien:
#   (a) Bekannte HTTP-/Telegram-Logger auf WARNING runter — silent in der
#       Standard-Operation.
#   (b) TokenScrubFilter als Sicherheitsnetz: scrubbt das Token-Pattern
#       \b\d+:[A-Za-z0-9_-]{35,}\b in JEDER Log-Message, falls in Zukunft
#       ein neuer HTTP-Client oder DEBUG-Level eingeschaltet wird.

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

for _noisy in ("httpx", "httpcore", "telegram", "telegram.ext", "telegram.bot", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


class TokenScrubFilter(logging.Filter):
    """Scrubbt Telegram-Bot-Token aus Log-Messages (Defense-in-Depth).

    Pattern bewusst OHNE `\\b`-Wort-Grenze davor: Telegram-API-URLs
    enthalten den Token in der Form `bot<n>:<35+chars>` — `\\b` zwischen
    `bot` und `<n>` matcht nicht, weil beides Word-Chars sind. Das
    Pattern `\\d+:[A-Za-z0-9_-]{35,}` ist spezifisch genug, um keine
    False-Positives in Timestamps oder kurzen ID-Strings zu erzeugen
    (35+-char-Hash hinter Doppelpunkt ist extrem ungewoehnlich).
    """

    _pat = re.compile(r"\d+:[A-Za-z0-9_-]{35,}")

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._pat.sub("[TOKEN]", record.msg)
        if record.args:
            record.args = tuple(
                self._pat.sub("[TOKEN]", str(a)) if isinstance(a, str) else a
                for a in record.args
            )
        return True


# Filter MUSS auf die Handler, nicht auf den Logger — sonst greift er
# nicht auf propagierte Records von child-Loggern wie httpx/telegram.
# (Stdlib-Logging-Eigenheit: Logger-Filter laufen vor Propagation,
# Handler-Filter laufen am tatsaechlichen Output-Punkt.)
_scrub_filter = TokenScrubFilter()
for _h in logging.getLogger().handlers:
    _h.addFilter(_scrub_filter)

logger = logging.getLogger(__name__)

from security import (
    ALLOWED_CHAT_ID,
    is_authorized,
    check_rate_limit,
    validate_container_name,
    validate_exec_command,
    sanitize_output,
)
from audit_log import (
    log_action,
    log_unauthorized,
    log_blocked_command,
    get_recent_logs,
)
from ai_agent import process_message, SEO_KEYWORDS
from docker_broker_client import DockerBrokerClient, DockerBrokerError

try:
    from seo_report import generate_seo_pdf
except ImportError:
    generate_seo_pdf = None

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]

docker_broker = DockerBrokerClient()

WEBAPP_DATA_MAX_BYTES = 4096
AI_REQUEST_VERSION = 2
AI_MODEL_SELECTIONS = frozenset({
    "auto",
    "claude-haiku-4-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-opus-4-5",
})
AI_V1_MODEL_ALIASES = {
    "auto": "auto",
    "haiku": "claude-haiku-4-5",
    "sonnet": "claude-sonnet-5",
    "opus": "claude-opus-4-8",
}
WEBAPP_CONTRACT_VERSION = "ai-request-v2"


@dataclass(frozen=True)
class AIRequest:
    message: str
    model: str


def _parse_ai_request(data: str) -> AIRequest:
    """Validiert den versionierten WebApp-KI-Vertrag ohne Prompt-Fallback."""
    if not isinstance(data, str) or len(data.encode("utf-8")) > WEBAPP_DATA_MAX_BYTES:
        raise ValueError("INVALID_AI_REQUEST")
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("INVALID_AI_REQUEST") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "type", "version", "message", "model"
    }:
        raise ValueError("INVALID_AI_REQUEST")
    if payload["type"] != "ai_request":
        raise ValueError("INVALID_AI_REQUEST")
    version = payload["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version not in {1, AI_REQUEST_VERSION}:
        raise ValueError("INVALID_AI_REQUEST")
    message = payload["message"]
    model = payload["model"]
    if not isinstance(message, str) or not message.strip():
        raise ValueError("INVALID_AI_REQUEST")
    if not isinstance(model, str):
        raise ValueError("INVALID_AI_REQUEST")
    # Rollout-Reihenfolge: zuerst diesen Bot deployen, danach das V2-Dashboard.
    # Nur das bereits ausgelieferte strukturierte V1-Format bleibt kompatibel;
    # unstrukturierter Freitext bekommt bewusst keinen Fallback.
    if version == 1:
        model = AI_V1_MODEL_ALIASES.get(model)
        if model is None:
            raise ValueError("INVALID_AI_REQUEST")
    elif model not in AI_MODEL_SELECTIONS:
        raise ValueError("INVALID_AI_REQUEST")
    return AIRequest(message=message, model=model)


def _versioned_webapp_url(url: str) -> str:
    """Erzwingt pro WebApp-Vertrag eine neue Telegram-/Browser-Cache-URL."""
    if not url:
        return ""
    parts = urlsplit(url)
    query = [
        (key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != "cloudbot_contract"
    ]
    query.append(("cloudbot_contract", WEBAPP_CONTRACT_VERSION))
    return urlunsplit(parts._replace(query=urlencode(query)))


def _broker_error_text(error: DockerBrokerError, container: str | None = None) -> str:
    """Stable, non-sensitive Telegram text for broker failures."""
    if error.code == "CONTAINER_NOT_FOUND":
        return f"Container '{container}' nicht gefunden." if container else "Container nicht gefunden."
    if error.code == "FILE_NOT_FOUND":
        return "Datei nicht gefunden."
    if error.code == "FILE_TOO_LARGE":
        return "Datei ist zu groß (maximal 8 MB)."
    if error.code == "FILE_READ_TIMEOUT":
        return "Datei konnte nicht rechtzeitig gelesen werden."
    if error.code == "EXEC_TIMEOUT":
        return "Zeitlimit bei der Ausführung überschritten."
    if error.code == "COMMAND_BLOCKED":
        return "Befehl wurde durch eine Sicherheitsregel blockiert."
    return "Docker-Dienst ist derzeit nicht erreichbar."


def authorized(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not is_authorized(chat_id):
            username = update.effective_user.username or "unbekannt"
            log_unauthorized(chat_id, username, func.__name__)
            await update.message.reply_text("Nicht autorisiert.")
            return
        allowed, msg = check_rate_limit(chat_id)
        if not allowed:
            await update.message.reply_text(msg)
            return
        return await func(update, context)
    return wrapper


@authorized
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        containers = await asyncio.to_thread(docker_broker.list_containers)
    except DockerBrokerError as exc:
        await update.message.reply_text("Docker-Dienst ist derzeit nicht erreichbar.")
        log_action(update.effective_chat.id, "status", "", exc.code, False)
        return
    if not containers:
        await update.message.reply_text("Keine Container gefunden.")
        log_action(update.effective_chat.id, "status", "", "keine Container", True)
        return
    lines = []
    for c in containers:
        icon = "+" if c.status == "running" else "-"
        lines.append(f"[{icon}] {c.name} -- {c.status}")
    result = "\n".join(lines)
    await update.message.reply_text(result)
    log_action(update.effective_chat.id, "status", "", f"{len(containers)} Container", True)


@authorized
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = context.args[0] if context.args else None
    valid, reason = validate_container_name(name)
    if not valid:
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "start", str(name), reason, False)
        return
    try:
        await asyncio.to_thread(docker_broker.start, name)
        await update.message.reply_text(f"{name} gestartet.")
        log_action(update.effective_chat.id, "start", name, "gestartet", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, name))
        log_action(update.effective_chat.id, "start", name, exc.code, False)


@authorized
async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = context.args[0] if context.args else None
    valid, reason = validate_container_name(name)
    if not valid:
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "stop", str(name), reason, False)
        return
    if name == "cloudbot":
        await update.message.reply_text("Der Bot kann sich nicht selbst stoppen.")
        log_action(update.effective_chat.id, "stop", name, "Selbst-Stop verhindert", False)
        return
    try:
        await asyncio.to_thread(docker_broker.stop, name)
        await update.message.reply_text(f"{name} gestoppt.")
        log_action(update.effective_chat.id, "stop", name, "gestoppt", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, name))
        log_action(update.effective_chat.id, "stop", name, exc.code, False)


@authorized
async def cmd_restart(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = context.args[0] if context.args else None
    valid, reason = validate_container_name(name)
    if not valid:
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "restart", str(name), reason, False)
        return
    if name == "cloudbot":
        await update.message.reply_text("Der Bot kann sich nicht selbst neustarten.")
        log_action(update.effective_chat.id, "restart", name, "Selbst-Restart verhindert", False)
        return
    try:
        await asyncio.to_thread(docker_broker.restart, name)
        await update.message.reply_text(f"{name} neugestartet.")
        log_action(update.effective_chat.id, "restart", name, "neugestartet", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, name))
        log_action(update.effective_chat.id, "restart", name, exc.code, False)


@authorized
async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = context.args[0] if context.args else None
    valid, reason = validate_container_name(name)
    if not valid:
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "logs", str(name), reason, False)
        return
    try:
        logs = await asyncio.to_thread(docker_broker.logs, name)
        if not logs.strip():
            logs = "(keine Logs)"
        logs = sanitize_output(logs)
        await update.message.reply_text(f"Logs von {name}:\n\n{logs[:3500]}")
        log_action(update.effective_chat.id, "logs", name, "gesendet", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, name))
        log_action(update.effective_chat.id, "logs", name, exc.code, False)


@authorized
async def cmd_exec(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args or len(context.args) < 2:
        await update.message.reply_text("Nutzung: /exec <container> <befehl>")
        return
    name = context.args[0]
    command = " ".join(context.args[1:])

    if name != "kali":
        reason = "Befehle dürfen ausschließlich im Kali-Container ausgeführt werden."
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "exec", f"{name} {command}", reason, False)
        return

    # Befehl validieren
    cmd_valid, cmd_reason = validate_exec_command(command)
    if not cmd_valid:
        await update.message.reply_text(f"Befehl blockiert: {cmd_reason}")
        log_blocked_command(update.effective_chat.id, command, cmd_reason)
        log_action(update.effective_chat.id, "exec", f"{name} {command}", cmd_reason, False)
        return

    try:
        result = await asyncio.to_thread(docker_broker.exec_kali, command, 180)
        output = result.stdout + result.stderr
        if not output.strip():
            output = "(keine Ausgabe)"
        output = sanitize_output(output)
        await update.message.reply_text(f"$ {command}\n\n{output[:3500]}")
        log_action(update.effective_chat.id, "exec", f"{name} {command}", output[:200], True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, name))
        log_action(update.effective_chat.id, "exec", f"{name} {command}", exc.code, False)


@authorized
async def cmd_audit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logs = get_recent_logs(20)
    await update.message.reply_text(f"Letzte Aktionen:\n\n{logs[:3500]}")
    log_action(update.effective_chat.id, "audit", "", "angezeigt", True)


@authorized
async def cmd_vpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        result = await asyncio.to_thread(docker_broker.vpn_status)
        output = result.stdout or result.stderr or "(keine Ausgabe)"
        output = sanitize_output(output)
        await update.message.reply_text(f"VPN Status:\n\n{output}")
        log_action(update.effective_chat.id, "vpn", "", "angezeigt", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, "nordvpn"))
        log_action(update.effective_chat.id, "vpn", "", exc.code, False)


@authorized
async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        ip = await asyncio.to_thread(_fetch_external_ip)
        if not ip:
            ip = "Konnte IP nicht ermitteln."
        await update.message.reply_text(f"Externe IP: {ip}")
        log_action(update.effective_chat.id, "ip", "", ip, True)
    except (OSError, ValueError) as exc:
        await update.message.reply_text("Externe IP konnte nicht ermittelt werden.")
        log_action(update.effective_chat.id, "ip", "", type(exc).__name__, False)


def _fetch_external_ip() -> str:
    """Runs through the controller's NordVPN network namespace."""
    with urllib.request.urlopen("https://ifconfig.me/ip", timeout=10) as response:
        return response.read(128).decode("ascii", errors="replace").strip()


@authorized
async def cmd_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Nutzung: /download <pfad>\nz.B. /download /root/data/scans/social_engineering/payload_reverse_tcp.exe")
        return
    filepath = " ".join(context.args)
    container_name = "kali"

    # Wenn Pfad mit container: beginnt, anderen Container nutzen
    if ":" in filepath and not filepath.startswith("/"):
        parts = filepath.split(":", 1)
        container_name = parts[0]
        filepath = parts[1]
        valid, reason = validate_container_name(container_name)
        if not valid:
            await update.message.reply_text(reason)
            return

    try:
        file_data = await asyncio.to_thread(
            docker_broker.download_file, container_name, filepath
        )
        filename = os.path.basename(filepath)
        await update.message.reply_document(
            document=io.BytesIO(file_data),
            filename=filename,
            caption=f"Datei von {container_name}:{filepath}"
        )
        log_action(update.effective_chat.id, "download", filepath, f"{len(file_data)} bytes", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, container_name))
        log_action(update.effective_chat.id, "download", filepath, exc.code, False)
    except Exception as e:
        await update.message.reply_text("Datei konnte nicht verarbeitet werden.")
        log_action(update.effective_chat.id, "download", filepath, type(e).__name__, False)


@authorized
async def cmd_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    path = " ".join(context.args) if context.args else "/root/data/scans"
    try:
        stdout = await asyncio.to_thread(docker_broker.list_files, path)
        if not stdout.strip():
            await update.message.reply_text(f"Keine Dateien in {path}")
            return
        lines = []
        for line in stdout.strip().split("\n")[:30]:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                try:
                    size = int(parts[0])
                except ValueError:
                    continue
                name = parts[1]
                if size > 1024 * 1024:
                    size_str = f"{size // (1024*1024)} MB"
                elif size > 1024:
                    size_str = f"{size // 1024} KB"
                else:
                    size_str = f"{size} B"
                lines.append(f"{size_str} -- {name}")
        output = "\n".join(lines)
        await update.message.reply_text(f"Dateien in {path}:\n\n{output[:3500]}\n\nDownload: /download <pfad>")
        log_action(update.effective_chat.id, "files", path, f"{len(lines)} Dateien", True)
    except DockerBrokerError as exc:
        await update.message.reply_text(_broker_error_text(exc, "kali"))
        log_action(update.effective_chat.id, "files", path, exc.code, False)
    except Exception as e:
        await update.message.reply_text("Dateiliste konnte nicht verarbeitet werden.")
        log_action(update.effective_chat.id, "files", path, type(e).__name__, False)


@authorized
async def cmd_hilfe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "Cloudbot Befehle\n\n"
        "/status -- Alle Container anzeigen\n"
        "/start <name> -- Container starten\n"
        "/stop <name> -- Container stoppen\n"
        "/restart <name> -- Container neustarten\n"
        "/logs <name> -- Letzte 30 Log-Zeilen\n"
        "/exec <name> <befehl> -- Befehl ausfuehren\n"
        "/vpn -- VPN-Status anzeigen\n"
        "/ip -- Externe IP anzeigen\n"
        "/files -- Erstellte Dateien auflisten\n"
        "/download <pfad> -- Datei herunterladen\n"
        "/audit -- Letzte 20 Aktionen anzeigen\n"
        "/app -- Dashboard oeffnen (Mini App)\n"
        "/hilfe -- Diese Hilfe anzeigen\n\n"
        "KI-Modus: Schreibe einfach eine Nachricht ohne /\n"
        "z.B. 'Scanne mein Netzwerk nach offenen Ports'"
    )
    await update.message.reply_text(text)
    log_action(update.effective_chat.id, "hilfe", "", "angezeigt", True)


WEBAPP_URL = _versioned_webapp_url(os.environ.get("WEBAPP_URL", ""))


@authorized
async def cmd_app(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not WEBAPP_URL:
        await update.message.reply_text("Mini App nicht konfiguriert (WEBAPP_URL fehlt).")
        return
    keyboard = ReplyKeyboardMarkup(
        [[KeyboardButton("Dashboard", web_app=WebAppInfo(url=WEBAPP_URL))]],
        resize_keyboard=True,
    )
    await update.message.reply_text("Oeffne das Dashboard:", reply_markup=keyboard)
    log_action(update.effective_chat.id, "app", "", "Dashboard geoeffnet", True)


async def handle_webapp_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        chat_id = update.effective_chat.id
        if not is_authorized(chat_id):
            username = update.effective_user.username or "unbekannt"
            log_unauthorized(chat_id, username, "webapp")
            await update.effective_message.reply_text("Nicht autorisiert.")
            return
        allowed, msg = check_rate_limit(chat_id)
        if not allowed:
            await update.effective_message.reply_text(msg)
            return

        if _already_processed(update.update_id):
            logger.info("Doppeltes Webapp-Update %s verworfen (Re-Auslieferung)", update.update_id)
            return

        data = update.effective_message.web_app_data.data
        if not isinstance(data, str):
            log_action(chat_id, "webapp", "type=invalid_payload", "abgelehnt", False)
            await update.effective_message.reply_text("Ungültige Dashboard-Anfrage.")
            return

        # Slash-Befehle direkt ausfuehren
        if data.startswith("/"):
            logger.info("Webapp-Slash-Befehl empfangen: %s", data.split(None, 1)[0][:32])
            log_action(chat_id, "webapp", "type=slash_command", "empfangen", True)
            parts = data.split(None, 2)
            cmd = parts[0].lstrip("/")
            args = parts[1:] if len(parts) > 1 else []
            context.args = args

            handlers = {
                "status": cmd_status,
                "vpn": cmd_vpn,
                "ip": cmd_ip,
                "audit": cmd_audit,
                "hilfe": cmd_hilfe,
                "logs": cmd_logs,
                "start": cmd_start,
                "stop": cmd_stop,
                "restart": cmd_restart,
                "files": cmd_files,
                "download": cmd_download,
            }

            if cmd == "exec" and len(args) >= 1:
                context.args = [args[0]] + ([" ".join(parts[2:])] if len(parts) > 2 else [])
                await cmd_exec(update, context)
            elif cmd in handlers:
                await handlers[cmd](update, context)
            else:
                await update.effective_message.reply_text(f"Unbekannter Befehl: /{cmd}")
            return

        # Strukturierter WebApp-Auftrag -> KI
        try:
            ai_request = _parse_ai_request(data)
        except ValueError:
            logger.warning("Ungueltige Webapp-KI-Payload (%d Bytes)", len(data.encode("utf-8")))
            log_action(chat_id, "webapp", "type=invalid_ai_request", "abgelehnt", False)
            await update.effective_message.reply_text("Ungültige Dashboard-Anfrage.")
            return
        metadata = (
            f"type=ai_request model={ai_request.model} "
            f"message_chars={len(ai_request.message)}"
        )
        logger.info("Webapp-KI-Auftrag empfangen: %s", metadata)
        log_action(chat_id, "webapp", metadata, "empfangen", True)
        is_seo = _is_seo_request(ai_request.message)
        await update.effective_message.reply_text("Ok Chef, bin dran...")
        response = await process_message(ai_request.message, chat_id, ai_request.model)
        if response:
            full_response = response
            while response:
                chunk = response[:4000]
                response = response[4000:]
                await update.effective_message.reply_text(chunk)
            if is_seo:
                await _send_seo_pdf(update.effective_message, full_response, ai_request.message)
    except Exception as e:
        logger.error("Webapp-Fehler: %s", e, exc_info=True)
        try:
            await update.effective_message.reply_text(f"Fehler: {str(e)[:500]}")
        except Exception:
            pass


def _is_seo_request(text):
    """Prueft ob die Nachricht eine SEO-Analyse anfordert."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in SEO_KEYWORDS)


async def _send_seo_pdf(message, response_text, user_text):
    """Generiert und sendet ein SEO-PDF wenn es eine SEO-Analyse war."""
    if not generate_seo_pdf:
        logger.warning("PDF-Generierung nicht verfuegbar (fpdf2 fehlt)")
        return
    try:
        pdf_path = generate_seo_pdf(response_text)
        with open(pdf_path, "rb") as f:
            await message.reply_document(
                document=f,
                filename=os.path.basename(pdf_path),
                caption="SEO-Analyse als PDF-Bericht"
            )
        log_action(
            message.chat.id, "seo_pdf", f"message_chars={len(user_text)}",
            "PDF erstellt", True,
        )
    except Exception as e:
        logger.error("PDF-Fehler: %s", e, exc_info=True)
        await message.reply_text(f"PDF konnte nicht erstellt werden: {str(e)[:200]}")


# === Update-Deduplizierung gegen Mehrfachantworten ===
# Hintergrund (Belegfall 2026-06-28): Ein KI-Lauf dauert teils >3 Min
# (Agent-Loop mit vielen Schritten). So lange blockiert der Handler.
# Telegram liefert ein Update nach Timeout ERNEUT aus, wenn es nicht
# zuegig bestaetigt wird -> derselbe Text wird 2-3x verarbeitet ->
# doppelte/dreifache Antwort. drop_pending_updates greift nur beim Start,
# nicht gegen Re-Auslieferung waehrend eines laufenden Handlers.
#
# Fix: jede update_id genau einmal verarbeiten. Wiederholte Auslieferungen
# desselben Updates werden sofort verworfen (vor "Ok Chef..." und vor dem
# KI-Aufruf). FIFO-begrenzt, damit die Menge nicht unbegrenzt waechst.

_processed_updates: set[int] = set()
_processed_order: list[int] = []
_PROCESSED_MAX = 1000


def _already_processed(update_id: int) -> bool:
    """True, wenn diese update_id schon gesehen wurde. Markiert sie sonst."""
    # Alle Aufrufer laufen als Tasks desselben asyncio-Eventloops. Diese
    # Funktion enthält kein await und ist damit bis zur Rückgabe atomar; ein
    # Thread-Lock wäre hier wirkungslos für Tasks und unnötig.
    if update_id in _processed_updates:
        return True
    _processed_updates.add(update_id)
    _processed_order.append(update_id)
    if len(_processed_order) > _PROCESSED_MAX:
        oldest = _processed_order.pop(0)
        _processed_updates.discard(oldest)
    return False


@authorized
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if _already_processed(update.update_id):
        logger.info("Doppeltes Update %s verworfen (Re-Auslieferung)", update.update_id)
        return
    user_text = update.message.text
    if not user_text:
        return
    is_seo = _is_seo_request(user_text)
    try:
        await update.message.reply_text("Ok Chef, bin dran...")
        response = await process_message(user_text, update.effective_chat.id, "auto")
        if response:
            full_response = response
            while response:
                chunk = response[:4000]
                response = response[4000:]
                await update.message.reply_text(chunk)
            if is_seo:
                await _send_seo_pdf(update.message, full_response, user_text)
    except Exception as e:
        await update.message.reply_text(f"Fehler: {str(e)[:500]}")
        log_action(
            update.effective_chat.id, "ai_chat",
            f"requested_model=auto message_chars={len(user_text)}",
            "TELEGRAM_HANDLER_FEHLER", False,
        )


# === Konnektivitaets-Waechter gegen Namespace-Verwaisung ===
# Hintergrund (Belegfall 2026-06-30): Der Bot laeuft mit
# network_mode: service:nordvpn und ist an den Netz-Namespace des
# nordvpn-Containers ZUM START-ZEITPUNKT gebunden. Startet nordvpn neu
# (z.B. nach Daemon-Tod), haengt der Bot am alten, toten Namespace:
# "Network is unreachable" zu allem, "Temporary failure in name
# resolution". Der nordvpn-Container kann den Bot nicht neu starten
# (kein Docker-Socket-Zugriff). Loesung: Der Bot prueft selbst seine
# Netz-Konnektivitaet und beendet sich bei anhaltendem Verlust ->
# Docker (restart: unless-stopped) startet ihn mit frischer
# Namespace-Bindung neu.
#
# Schwelle bewusst tolerant (3x60s): kurze NordLynx-Serverwechsel sollen
# KEINEN Neustart ausloesen, nur ein echter, anhaltender Verlust.

_WATCHDOG_INTERVAL = 60          # Sekunden zwischen Checks
_WATCHDOG_MAX_FAILURES = 3       # so viele Fehlschlaege in Folge -> Neustart
_WATCHDOG_PROBE_HOST = "api.telegram.org"  # muss erreichbar sein, damit der Bot arbeitet


def _connectivity_ok() -> bool:
    """True, wenn der Bot Namen aufloesen + eine TCP-Verbindung oeffnen kann.

    DNS-Aufloesung + TCP-Connect zu Telegram pruefen Namespace-Bindung,
    Tunnel und DNS in einem billigen Check — genau die Kette, die beim
    Namespace-Verwaisungs-Ausfall reisst.
    """
    try:
        ip = socket.gethostbyname(_WATCHDOG_PROBE_HOST)
        with socket.create_connection((ip, 443), timeout=10):
            return True
    except OSError:
        return False


async def _connectivity_watchdog():
    failures = 0
    while True:
        await asyncio.sleep(_WATCHDOG_INTERVAL)
        ok = await asyncio.to_thread(_connectivity_ok)
        if ok:
            if failures:
                logger.info("Konnektivitaet wiederhergestellt (nach %d Fehlschlaegen).", failures)
            failures = 0
            continue
        failures += 1
        logger.warning(
            "Konnektivitaets-Check fehlgeschlagen (%d/%d) — moegliche Namespace-Verwaisung.",
            failures, _WATCHDOG_MAX_FAILURES,
        )
        if failures >= _WATCHDOG_MAX_FAILURES:
            logger.error(
                "Netzwerk anhaltend tot — Bot beendet sich fuer frischen "
                "Namespace-Neustart durch Docker (restart: unless-stopped)."
            )
            os._exit(1)


async def _post_init(app: Application) -> None:
    """Startet den Konnektivitaets-Waechter im laufenden Event-Loop."""
    app.create_task(_connectivity_watchdog())


def main():
    app = Application.builder().token(TOKEN).post_init(_post_init).build()
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("restart", cmd_restart))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CommandHandler("exec", cmd_exec))
    app.add_handler(CommandHandler("audit", cmd_audit))
    app.add_handler(CommandHandler("vpn", cmd_vpn))
    app.add_handler(CommandHandler("ip", cmd_ip))
    app.add_handler(CommandHandler("app", cmd_app))
    app.add_handler(CommandHandler("files", cmd_files))
    app.add_handler(CommandHandler("download", cmd_download))
    app.add_handler(CommandHandler("hilfe", cmd_hilfe))
    app.add_handler(MessageHandler(filters.StatusUpdate.WEB_APP_DATA, handle_webapp_data))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    logger.info("Cloudbot laeuft... (mit KI + Mini App)")
    logger.info("WEBAPP_URL: %s", WEBAPP_URL or "NICHT GESETZT")
    # drop_pending_updates=True: verwirft beim Start alte/aufgestaute Updates.
    # Schuetzt gegen doppelte Berichte nach Neustart oder nach einem
    # kurzzeitigen Zwei-Instanzen-getUpdates-Konflikt (Telegram liefert dann
    # gestaute Updates sonst an die ueberlebende Instanz erneut aus).
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
