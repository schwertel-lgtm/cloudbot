# CLAUDE CONTEXT - Maschinenlesbare Projektdatei
# Lies diese Datei um sofort auf dem aktuellen Stand zu sein.
# Letzte Aktualisierung: 2026-03-29

## IDENTITAET
- Benutzer: Ralph
- Sprache: Deutsch
- Rolle: Projektinhaber, alleiniger Auftraggeber

## PROJEKT: Cloudbot
- Zweck: Telegram-Bot zur Docker-Container-Steuerung auf Synology NAS
- Status: Laeuft in Produktion (seit 2026-03-29)

## INFRASTRUKTUR
- NAS: Synology DS220+ | Hostname: RS-NAS | IP: 192.168.178.28
- SSH: dole4711@192.168.178.28 | Auth: Key (ed25519) | Port: 22
- SSH-Key: C:\Users\ralph\.ssh\id_ed25519
- Docker: /volume1/@appstore/ContainerManager/usr/bin/docker (v24.0.2)
- Docker Compose: v2.20.1
- Sudo: passwortlos fuer Docker (/etc/sudoers.d/dole4711-docker)
- Kernel: 4.4.302+ (kein cpus/pids_limit Support)
- SCP nicht verfuegbar, Dateitransfer: cat datei | ssh user@host "cat > ziel"

## VPN
- NordVPN via eigenem Docker-Container (offizieller NordVPN CLI)
- Technologie: NordLynx (WireGuard)
- Server: Netherlands (Amsterdam)
- Token: in /volume1/docker/cloudbot/.env (NORDVPN_TOKEN)
- Killswitch: aktiv (wird nach erfolgreicher Verbindung aktiviert)
- LAN-Zugriff: 192.168.178.0/24 + 172.16.0.0/12 whitelisted
- NordVPN Firewall: off (noetig wegen iptables-legacy/nft Konflikt auf Synology)
- Alle Container (cloudbot + kali) nutzen network_mode: service:nordvpn
- Entrypoint: nordvpn/entrypoint.sh (Login, Settings, Connect, Killswitch, Watchdog)
- Wichtig: printf 'n\n' vor Login noetig wegen Analytics-Abfrage
- iptables muss auf legacy gesetzt werden (Synology Kernel Kompatibilitaet)

## PFADE
- Entwicklung (Windows): C:\Users\ralph\claude\Neugruendung\
- Produktion (NAS): /volume1/docker/cloudbot/
- Bot-Code: cloudbot/bot.py, cloudbot/security.py, cloudbot/audit_log.py
- Kali: kali/Dockerfile
- VPN: nordvpn/Dockerfile, nordvpn/entrypoint.sh
- Config: .env (nur auf NAS, NICHT im Git)
- Logs: Volume bot-logs -> /app/logs/audit.log, /app/logs/security.log
- Docs: docs/DOKUMENTATION.md, docs/CLAUDE_CONTEXT.md, docs/ARBEITSDATEI.md

## CONTAINER (laufend)
- nordvpn: ubuntu:22.04 + NordVPN CLI | VPN-Gateway | 512MB RAM
- cloudbot: python:3.12-slim | bot.py | network_mode: service:nordvpn | 512MB RAM
- kali: kali-rolling + headless | network_mode: service:nordvpn | 2GB RAM
- Spion: alter Kali-Container (kalilinux/kali-rolling:latest) | noch aktiv, kann entfernt werden

## TELEGRAM BOT
- Token: in /volume1/docker/cloudbot/.env
- Chat-ID: in /volume1/docker/cloudbot/.env
- Befehle: /status /start /stop /restart /logs /exec /audit /hilfe
- Nur Ralphs Chat-ID ist autorisiert

## SICHERHEIT
- VPN: Gesamter externer Traffic laeuft ueber NordVPN (Niederlande)
- Killswitch: Kein Traffic ohne VPN-Verbindung
- Container-Whitelist: {kali, cloudbot}
- Command-Blocklist: rm -rf, reverse shells, sudo, docker, mount, eval, mining, exfiltration
- Docker Socket: read-only gemountet
- Audit-Logging: JSON-Lines, 5MB Rotation
- Output-Sanitierung: Tokens/Passwoerter werden gefiltert
- CLAUDE.md: Sicherheitsregeln fuer Claude Code (kein externer Code, keine Backdoors)

## DEPLOYMENT-BEFEHLE
```
# Datei uebertragen:
cat LOKALE_DATEI | ssh dole4711@192.168.178.28 "cat > /volume1/docker/cloudbot/ZIELPFAD"

# Build + Start:
ssh dole4711@192.168.178.28 "cd /volume1/docker/cloudbot && sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose build && sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose up -d"

# Nur NordVPN neu bauen:
ssh dole4711@192.168.178.28 "cd /volume1/docker/cloudbot && sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose down && sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose build nordvpn && sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose up -d"

# Logs:
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker logs cloudbot 2>&1 | tail -20"

# VPN Status:
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker exec nordvpn nordvpn status"

# Status:
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker ps -a"
```

## BEKANNTE LIMITIERUNGEN
- Synology-Kernel: kein cpus/pids_limit
- Docker Socket: root:root, kein Non-Root-Zugriff moeglich
- SCP deaktiviert auf Synology
- Docker CLI nicht im PATH
- NordVPN Firewall muss off sein (iptables-legacy/nft Konflikt)
- NordVPN Analytics-Abfrage muss per printf 'n\n' beantwortet werden

## OFFENE PUNKTE
- Synology Firewall (Phase 8) noch nicht konfiguriert
- Claude API Anbindung fuer autonomes Arbeiten (optional)
- Alter "Spion" Container aufraeumen
