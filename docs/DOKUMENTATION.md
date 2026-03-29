# Cloudbot Projekt - Komplette Dokumentation

## Projektueberblick

Ein Telegram-gesteuerter Bot ("Cloudbot") der auf einer Synology DS220+ NAS laeuft und Docker-Container (insbesondere Kali Linux) fernsteuern kann. Der Bot nimmt Befehle ausschliesslich vom autorisierten Benutzer (Ralph) ueber Telegram entgegen.

---

## Hardware & System

| Komponente | Details |
|---|---|
| NAS | Synology DS220+ (Geminilake / Celeron J4025) |
| RAM | 16 GB |
| OS | DSM mit Linux Kernel 4.4.302+ |
| Hostname | RS-NAS |
| IP (lokal) | 192.168.178.28 |
| SSH User | dole4711 |
| SSH Auth | Key-basiert (ed25519), kein Passwort |
| SSH Key | C:\Users\ralph\.ssh\id_ed25519 |
| Docker | Version 24.0.2 (Container Manager) |
| Docker Pfad | /volume1/@appstore/ContainerManager/usr/bin/docker |
| Docker Compose | Version 2.20.1 |
| Sudo | Passwortlos fuer Docker-Befehle (/etc/sudoers.d/dole4711-docker) |

---

## Verzeichnisstruktur

### Auf dem Windows-PC (Entwicklung)
```
C:\Users\ralph\claude\Neugruendung\
  CLAUDE.md                  # Sicherheitsregeln fuer Claude Code
  docker-compose.yml         # Container-Orchestrierung
  .env.example               # Vorlage fuer Umgebungsvariablen
  .gitignore
  docs/
    DOKUMENTATION.md         # Diese Datei
    CLAUDE_CONTEXT.md        # Maschinenlesbare Kontextdatei fuer Claude
    ARBEITSDATEI.md          # Arbeitsdatei fuer Wissensstand
  cloudbot/
    bot.py                   # Telegram Bot (Hauptdatei)
    security.py              # Sicherheitsmodul
    audit_log.py             # Logging-Modul
    Dockerfile               # Container-Definition Cloudbot
    requirements.txt         # Python-Abhaengigkeiten
  kali/
    Dockerfile               # Container-Definition Kali Linux
```

### Auf der Synology NAS (Produktion)
```
/volume1/docker/cloudbot/
  .env                       # Echte Credentials (Token + Chat-ID)
  docker-compose.yml
  cloudbot/
    bot.py
    security.py
    audit_log.py
    Dockerfile
    requirements.txt
  kali/
    Dockerfile
```

---

## Container-Architektur

### Container: kali
- **Image:** kalilinux/kali-rolling mit kali-linux-headless, exploitdb, wordlists
- **Netzwerk:** network_mode: service:nordvpn (Traffic ueber VPN)
- **RAM-Limit:** 2 GB
- **Volume:** kali-data:/root/data

### Container: nordvpn
- **Image:** ubuntu:22.04 mit offiziellem NordVPN CLI
- **Netzwerk:** Standard Bridge (Internet-Zugang fuer VPN-Tunnel)
- **Technologie:** NordLynx (WireGuard)
- **Server:** Netherlands (Amsterdam)
- **Capabilities:** NET_ADMIN, NET_RAW
- **Device:** /dev/net/tun
- **RAM-Limit:** 512 MB
- **Entrypoint:** Login, Einstellungen, Connect, Killswitch, Watchdog

### Container: cloudbot
- **Image:** python:3.12-slim mit python-telegram-bot + docker SDK
- **Netzwerk:** network_mode: service:nordvpn (Traffic ueber VPN)
- **Docker Socket:** /var/run/docker.sock (read-only gemountet)
- **RAM-Limit:** 512 MB
- **Volume:** bot-logs:/app/logs (Audit-Logs)

### Container: Spion (alt)
- **Image:** kalilinux/kali-rolling:latest
- **Status:** Laeuft noch, wurde vor dem Projekt erstellt
- **Hinweis:** Kann aufgeraeumt werden

---

## Telegram Bot

### Credentials
- **Bot Token:** In /volume1/docker/cloudbot/.env gespeichert
- **Chat-ID:** In /volume1/docker/cloudbot/.env gespeichert
- **Nur Ralph ist autorisiert** (Chat-ID Pruefung)

### Verfuegbare Befehle
| Befehl | Beschreibung |
|---|---|
| /status | Alle Container anzeigen |
| /start <name> | Container starten |
| /stop <name> | Container stoppen |
| /restart <name> | Container neustarten |
| /logs <name> | Letzte 30 Log-Zeilen |
| /exec <name> <befehl> | Befehl im Container ausfuehren |
| /audit | Letzte 20 Audit-Log-Eintraege |
| /hilfe | Hilfe anzeigen |

---

## Sicherheitsmassnahmen

### 1. Autorisierung
- Nur die konfigurierte Telegram Chat-ID wird akzeptiert
- Unautorisierte Zugriffe werden in security.log geloggt

### 2. Command-Blocklist (security.py)
Folgende Befehlsmuster werden blockiert:
- Dateisystem-Zerstoerung (rm -rf /, mkfs, dd)
- Reverse Shells (nc, bash -i, python socket)
- Privilege Escalation (sudo, su, passwd, chmod 777)
- System-Manipulation (iptables, docker, mount, systemctl)
- Code-Injection (eval, exec, backticks)
- Crypto-Mining (xmrig, minerd)
- Daten-Exfiltration (curl POST, wget POST)

### 3. Container-Whitelist
Nur Container "kali" und "cloudbot" sind erlaubt. Der Bot kann sich nicht selbst stoppen.

### 4. VPN (NordVPN)
- Gesamter externer Traffic laeuft ueber NordVPN (Niederlande/Amsterdam)
- Technologie: NordLynx (WireGuard-basiert)
- Eigener Docker-Container mit offiziellem NordVPN CLI
- Killswitch: aktiv (kein Traffic ohne VPN)
- LAN-Zugriff (192.168.178.0/24) bleibt erlaubt
- Automatische Reconnect-Pruefung alle 5 Minuten
- Abo aktiv bis 27.03.2027

### 5. Netzwerk-Isolation
- Alle Container nutzen network_mode: service:nordvpn (kein eigenes Netzwerk)
- Docker Socket: read-only

### 6. Audit-Logging
- Alle Aktionen: /app/logs/audit.log (JSON-Lines, 5MB Rotation)
- Sicherheitsvorfaelle: /app/logs/security.log (2MB Rotation)
- Output-Sanitierung: Tokens und Passwoerter werden gefiltert

---

## Deployment-Anleitung

### Dateien auf NAS uebertragen
```bash
# Von Windows PC aus:
cat datei.py | ssh dole4711@192.168.178.28 "cat > /volume1/docker/cloudbot/cloudbot/datei.py"
```

### Container bauen und starten
```bash
ssh dole4711@192.168.178.28 "cd /volume1/docker/cloudbot && \
  sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose build && \
  sudo /volume1/@appstore/ContainerManager/usr/bin/docker compose up -d"
```

### Logs pruefen
```bash
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker logs cloudbot 2>&1 | tail -20"
```

### Container-Status
```bash
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker ps -a"
```

### VPN-Status pruefen
```bash
ssh dole4711@192.168.178.28 "sudo /volume1/@appstore/ContainerManager/usr/bin/docker exec nordvpn nordvpn status"
```

---

## Bekannte Einschraenkungen des Synology-Kernels
- **Kein CPU CFS Scheduler:** `cpus` und `pids_limit` in docker-compose nicht unterstuetzt
- **Docker Socket:** Gehoert root:root, Non-Root User koennen nicht direkt zugreifen
- **SCP:** Nicht verfuegbar, Dateitransfer ueber `cat | ssh`
- **Docker CLI:** Nicht im PATH, voller Pfad noetig

---

## Chronologie (29.03.2026)
1. SSH-Key Authentifizierung eingerichtet (ed25519)
2. Sudo ohne Passwort fuer Docker konfiguriert
3. Bestehende Projektdateien analysiert
4. Sicherheitsplan in 8 Phasen erstellt
5. CLAUDE.md mit Sicherheitsregeln erstellt
6. security.py (Blocklist, Whitelist, Validierung) erstellt
7. audit_log.py (strukturiertes Logging) erstellt
8. bot.py ueberarbeitet (Security + Logging integriert)
9. docker-compose.yml gehaertet (Netzwerk-Isolation, Read-Only Socket, RAM-Limits)
10. Dockerfile gehaertet
11. Alles auf NAS deployed und erfolgreich getestet
12. NordVPN Docker-Container erstellt (eigenes Image mit offiziellem CLI)
13. VPN-Verbindung zu Niederlande (Amsterdam) hergestellt
14. Killswitch aktiviert
15. Alle Container ueber VPN geroutet
16. Dokumentation aktualisiert
