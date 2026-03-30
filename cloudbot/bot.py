import os
import docker
from telegram import Update, WebAppInfo, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

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
from ai_agent import process_message

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
        result = container.exec_run(command, demux=True)
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


@authorized
async def handle_webapp_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = update.effective_message.web_app_data.data
    chat_id = update.effective_chat.id
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
        }

        if cmd == "exec" and len(args) >= 2:
            context.args = [args[0], " ".join(args[1:])] if len(parts) > 2 else args
            await cmd_exec(update, context)
        elif cmd in handlers:
            await handlers[cmd](update, context)
        else:
            await update.message.reply_text(f"Unbekannter Befehl: /{cmd}")
        return

    # Freitext -> KI
    try:
        response = await process_message(data, chat_id)
        if response:
            while response:
                chunk = response[:4000]
                response = response[4000:]
                await update.message.reply_text(chunk)
    except Exception as e:
        await update.message.reply_text(f"Fehler: {str(e)[:500]}")
        log_action(chat_id, "ai_chat", data[:100], str(e)[:200], False)


@authorized
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    if not user_text:
        return
    try:
        response = await process_message(user_text, update.effective_chat.id)
        if response:
            while response:
                chunk = response[:4000]
                response = response[4000:]
                await update.message.reply_text(chunk)
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
    app.add_handler(CommandHandler("hilfe", cmd_hilfe))
    app.add_handler(MessageHandler(filters.StatusUpdate.WEB_APP_DATA, handle_webapp_data))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("Cloudbot laeuft... (mit KI + Mini App)")
    app.run_polling()


if __name__ == "__main__":
    main()
