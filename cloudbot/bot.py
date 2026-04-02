import os
import io
import tarfile
import logging
import docker
from telegram import Update, WebAppInfo, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from security import (
    ALLOWED_CHAT_ID,
    is_authorized,
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

try:
    from seo_report import generate_seo_pdf
except ImportError:
    generate_seo_pdf = None

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]

client = docker.from_env()


def authorized(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not is_authorized(chat_id):
            username = update.effective_user.username or "unbekannt"
            log_unauthorized(chat_id, username, func.__name__)
            await update.message.reply_text("Nicht autorisiert.")
            return
        return await func(update, context)
    return wrapper


@authorized
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    containers = client.containers.list(all=True)
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
        container = client.containers.get(name)
        container.start()
        await update.message.reply_text(f"{name} gestartet.")
        log_action(update.effective_chat.id, "start", name, "gestartet", True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{name}' nicht gefunden.")
        log_action(update.effective_chat.id, "start", name, "nicht gefunden", False)


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
        container = client.containers.get(name)
        container.stop()
        await update.message.reply_text(f"{name} gestoppt.")
        log_action(update.effective_chat.id, "stop", name, "gestoppt", True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{name}' nicht gefunden.")
        log_action(update.effective_chat.id, "stop", name, "nicht gefunden", False)


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
        container = client.containers.get(name)
        container.restart()
        await update.message.reply_text(f"{name} neugestartet.")
        log_action(update.effective_chat.id, "restart", name, "neugestartet", True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{name}' nicht gefunden.")
        log_action(update.effective_chat.id, "restart", name, "nicht gefunden", False)


@authorized
async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = context.args[0] if context.args else None
    valid, reason = validate_container_name(name)
    if not valid:
        await update.message.reply_text(reason)
        log_action(update.effective_chat.id, "logs", str(name), reason, False)
        return
    try:
        container = client.containers.get(name)
        logs = container.logs(tail=30).decode("utf-8", errors="replace")
        if not logs.strip():
            logs = "(keine Logs)"
        logs = sanitize_output(logs)
        await update.message.reply_text(f"Logs von {name}:\n\n{logs[:3500]}")
        log_action(update.effective_chat.id, "logs", name, "gesendet", True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{name}' nicht gefunden.")
        log_action(update.effective_chat.id, "logs", name, "nicht gefunden", False)


@authorized
async def cmd_exec(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args or len(context.args) < 2:
        await update.message.reply_text("Nutzung: /exec <container> <befehl>")
        return
    name = context.args[0]
    command = " ".join(context.args[1:])

    # Container validieren
    valid, reason = validate_container_name(name)
    if not valid:
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
        container = client.containers.get(name)
        result = container.exec_run(["bash", "-c", command], demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        stderr = result.output[1].decode("utf-8", errors="replace") if result.output[1] else ""
        output = stdout + stderr
        if not output.strip():
            output = "(keine Ausgabe)"
        output = sanitize_output(output)
        await update.message.reply_text(f"$ {command}\n\n{output[:3500]}")
        log_action(update.effective_chat.id, "exec", f"{name} {command}", output[:200], True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{name}' nicht gefunden.")
        log_action(update.effective_chat.id, "exec", f"{name} {command}", "nicht gefunden", False)
    except docker.errors.APIError as e:
        await update.message.reply_text("Fehler bei der Ausfuehrung.")
        log_action(update.effective_chat.id, "exec", f"{name} {command}", str(e)[:200], False)


@authorized
async def cmd_audit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logs = get_recent_logs(20)
    await update.message.reply_text(f"Letzte Aktionen:\n\n{logs[:3500]}")
    log_action(update.effective_chat.id, "audit", "", "angezeigt", True)


@authorized
async def cmd_vpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        container = client.containers.get("nordvpn")
        result = container.exec_run("nordvpn status", demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        stderr = result.output[1].decode("utf-8", errors="replace") if result.output[1] else ""
        output = stdout or stderr or "(keine Ausgabe)"
        output = sanitize_output(output)
        await update.message.reply_text(f"VPN Status:\n\n{output}")
        log_action(update.effective_chat.id, "vpn", "", "angezeigt", True)
    except docker.errors.NotFound:
        await update.message.reply_text("NordVPN-Container nicht gefunden.")
        log_action(update.effective_chat.id, "vpn", "", "nicht gefunden", False)


@authorized
async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        container = client.containers.get("nordvpn")
        result = container.exec_run("curl -s --max-time 10 ifconfig.me", demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        stderr = result.output[1].decode("utf-8", errors="replace") if result.output[1] else ""
        ip = stdout.strip() if stdout.strip() else "Konnte IP nicht ermitteln."
        await update.message.reply_text(f"Externe IP: {ip}")
        log_action(update.effective_chat.id, "ip", "", ip, True)
    except docker.errors.NotFound:
        await update.message.reply_text("NordVPN-Container nicht gefunden.")
        log_action(update.effective_chat.id, "ip", "", "nicht gefunden", False)


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
        container = client.containers.get(container_name)
        try:
            archive, _ = container.get_archive(filepath)
            tar_data = b"".join(archive)
            tar_stream = io.BytesIO(tar_data)
            with tarfile.open(fileobj=tar_stream) as tar:
                member = tar.getmembers()[0]
                if member.isfile():
                    f = tar.extractfile(member)
                    file_data = f.read()
                else:
                    await update.message.reply_text(f"'{filepath}' ist ein Verzeichnis. Nutze /files um Dateien aufzulisten.")
                    return
        except docker.errors.NotFound:
            # Fallback fuer tmpfs-Pfade: Datei per cat lesen
            result = container.exec_run(["bash", "-c", f"cat '{filepath}'"], demux=True)
            stdout = result.output[0] if result.output[0] else b""
            if not stdout:
                await update.message.reply_text(f"Datei nicht gefunden: {filepath}")
                log_action(update.effective_chat.id, "download", filepath, "nicht gefunden", False)
                return
            file_data = stdout
        filename = os.path.basename(filepath)
        await update.message.reply_document(
            document=io.BytesIO(file_data),
            filename=filename,
            caption=f"Datei von {container_name}:{filepath}"
        )
        log_action(update.effective_chat.id, "download", filepath, f"{len(file_data)} bytes", True)
    except docker.errors.NotFound:
        await update.message.reply_text(f"Container '{container_name}' nicht gefunden.")
        log_action(update.effective_chat.id, "download", filepath, "nicht gefunden", False)
    except Exception as e:
        await update.message.reply_text(f"Fehler beim Download: {str(e)[:300]}")
        log_action(update.effective_chat.id, "download", filepath, str(e)[:200], False)


@authorized
async def cmd_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    path = " ".join(context.args) if context.args else "/root/data/scans"
    try:
        container = client.containers.get("kali")
        result = container.exec_run(f"find {path} -maxdepth 2 -type f -printf '%s %p\\n'", demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        if not stdout.strip():
            await update.message.reply_text(f"Keine Dateien in {path}")
            return
        lines = []
        for line in stdout.strip().split("\n")[:30]:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                size = int(parts[0])
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
    except Exception as e:
        await update.message.reply_text(f"Fehler: {str(e)[:300]}")


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


WEBAPP_URL = os.environ.get("WEBAPP_URL", "")


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
            logger.warning("Webapp: Unautorisierter Zugriff von %s", chat_id)
            return

        data = update.effective_message.web_app_data.data
        logger.info("Webapp-Daten empfangen: %s", data[:100])
        log_action(chat_id, "webapp", data[:100], "empfangen", True)

        # Slash-Befehle direkt ausfuehren
        if data.startswith("/"):
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

        # Freitext -> KI
        is_seo = _is_seo_request(data)
        await update.effective_message.reply_text("Ok Chef, bin dran...")
        response = await process_message(data, chat_id)
        if response:
            full_response = response
            while response:
                chunk = response[:4000]
                response = response[4000:]
                await update.effective_message.reply_text(chunk)
            if is_seo:
                await _send_seo_pdf(update.effective_message, full_response, data)
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
        log_action(message.chat.id, "seo_pdf", user_text[:50], pdf_path, True)
    except Exception as e:
        logger.error("PDF-Fehler: %s", e, exc_info=True)
        await message.reply_text(f"PDF konnte nicht erstellt werden: {str(e)[:200]}")


@authorized
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    if not user_text:
        return
    is_seo = _is_seo_request(user_text)
    try:
        await update.message.reply_text("Ok Chef, bin dran...")
        response = await process_message(user_text, update.effective_chat.id)
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
        log_action(update.effective_chat.id, "ai_chat", user_text[:100], str(e)[:200], False)


def main():
    app = Application.builder().token(TOKEN).build()
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
    app.run_polling()


if __name__ == "__main__":
    main()
