# ARBEITSDATEI - Aktueller Wissensstand & Arbeitslog

## Schnellstart fuer neue Session
1. Lies docs/CLAUDE_CONTEXT.md fuer den kompletten technischen Kontext
2. Lies CLAUDE.md fuer die Sicherheitsregeln
3. Pruefe den aktuellen Status auf dem NAS:
   ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker ps -a"
4. Pruefe VPN-Status:
   ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker exec nordvpn nordvpn status"

## Aktuelle Aufgaben

### Erledigt (2026-03-29)
- [x] SSH-Key Authentifizierung eingerichtet
- [x] Sudo ohne Passwort fuer Docker
- [x] security.py: Command-Blocklist, Container-Whitelist, Output-Sanitierung
- [x] audit_log.py: JSON-Lines Audit-Logging mit Rotation
- [x] bot.py: Alle Handler abgesichert mit Validierung + Logging
- [x] docker-compose.yml: Netzwerk-Isolation, Read-Only Socket, RAM-Limits
- [x] Dockerfile: Gehaertet
- [x] Deployment auf NAS erfolgreich
- [x] Bot reagiert auf Telegram-Befehle
- [x] NordVPN Integration (eigener Container, NordLynx, Niederlande)
- [x] Killswitch aktiv
- [x] Alle Container (cloudbot + kali) laufen ueber VPN
- [x] Dokumentation erstellt (DOKUMENTATION.md, CLAUDE_CONTEXT.md, ARBEITSDATEI.md)

### Erledigt (2026-03-30)
- [x] /vpn und /ip Befehle eingebaut
- [x] nordvpn zur Container-Whitelist hinzugefuegt
- [x] NordVPN Healthcheck in docker-compose.yml (kali+cloudbot starten erst wenn VPN healthy)
- [x] GitHub Repo public (schwertel-lgtm/cloudbot) + GitHub Pages aktiviert
- [x] gh CLI installiert und eingerichtet
- [x] Telegram Mini App (webapp/index.html) mit 4 Tabs: Befehle, Scan, OSINT, SE
- [x] /app Befehl oeffnet Mini App Dashboard in Telegram
- [x] web_app_data Handler fuer Mini App Integration
- [x] Bot-Befehle als Buttons in command-generator.html (PC-Version)
- [x] Social Engineer Toolkit (SET) Integration (Phishing, Credential Harvest, Payload, QR-Code)
- [x] KI-Agent: 180s Timeout, Endbericht-Anforderung, besseres Logging
- [x] Command-Limit auf 2000 Zeichen erhoeht
- [x] Antwort-Limit entfernt (wird in 4000-Zeichen-Chunks gesendet)
- [x] /files Befehl (Dateien im Kali-Container auflisten)
- [x] /download Befehl (Dateien als Telegram-Dokument senden)
- [x] Logging mit Zeichenanzahl und Zeitangabe
- [x] Alter "Spion" Container ist entfernt
- [x] Claude API Anbindung funktioniert (ai_agent.py mit Tool-Use)
- [x] Git-Repository auf GitHub mit regelmaessigen Commits

### Offen
- [ ] Synology Firewall konfigurieren (Phase 8)
- [ ] Toter Code aufraeumen (bot/, main.py, requirements.txt im Root)

## Bot-Befehle (aktuell)
/status, /start, /stop, /restart, /logs, /exec, /vpn, /ip, /files, /download, /audit, /app, /hilfe

## Wichtige Erkenntnisse
- Synology Kernel 4.4 unterstuetzt KEIN cpus/pids_limit in Docker
- Docker Socket gehoert root:root -> Non-Root User funktioniert nicht
- SCP ist auf der Synology deaktiviert -> cat | ssh verwenden
- Docker CLI ist NICHT im PATH -> voller Pfad: /volume1/@appstore/ContainerManager/usr/bin/docker
- GID 999 existiert bereits im python:3.12-slim Image
- NordVPN: iptables muss auf legacy gesetzt werden (Synology Kernel)
- NordVPN: Firewall-Setting muss off sein, sonst scheitert die Verbindung
- NordVPN: Analytics-Abfrage blockiert Login -> printf 'n\n' pipen
- NordVPN: bubuntux/nordvpn Image funktioniert NICHT -> eigenes Image mit offiziellem CLI
- NordVPN Abo aktiv bis 27.03.2027
- Anthropic API Key (Bot) ist separat von Claude Code Abo -> getrennte Abrechnung
- KI gibt Endbericht nur als Text wenn explizit angefordert (Workaround in process_message)
- docker exec_run unterstuetzt keine Pipes/Redirects -> bash -c 'cmd' verwenden
- GitHub Pages URL: https://schwertel-lgtm.github.io/cloudbot/webapp/
- Telegram Mini App: sendData() schliesst App nach jedem Befehl

## Aenderungsprotokoll
| Datum | Aenderung | Dateien |
|---|---|---|
| 2026-03-29 | Projekt initial aufgesetzt | alle |
| 2026-03-29 | Sicherheitsplan Phase 1-6 implementiert | security.py, audit_log.py, bot.py, docker-compose.yml, Dockerfile, CLAUDE.md |
| 2026-03-29 | Deployment auf NAS | alle Dateien auf /volume1/docker/cloudbot/ |
| 2026-03-29 | NordVPN Integration | nordvpn/Dockerfile, nordvpn/entrypoint.sh, docker-compose.yml, .env |
| 2026-03-29 | Dokumentation aktualisiert | docs/* |
| 2026-03-30 | /vpn, /ip Befehle + nordvpn Whitelist | bot.py, security.py |
| 2026-03-30 | NordVPN Healthcheck | docker-compose.yml |
| 2026-03-30 | GitHub Repo public + Pages | .gitignore, webapp/index.html |
| 2026-03-30 | Telegram Mini App | webapp/index.html, bot.py |
| 2026-03-30 | SET Integration | webapp/index.html, docs/command-generator.html |
| 2026-03-30 | KI-Agent Timeout + Endbericht-Fix | ai_agent.py |
| 2026-03-30 | /files + /download Befehle | bot.py |
| 2026-03-30 | Command-Limit 2000, kein Antwort-Limit | security.py, ai_agent.py |
