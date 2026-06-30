# §10 Cross-Review-Briefing — NordVPN-Ausfall-Härtung (2026-06-30)

## Kontext
Auf einer Synology-NAS laufen 3 Docker-Container: `nordvpn` (VPN-Gateway),
`cloudbot` (Telegram-gesteuerter Python-Bot) und `kali`. `cloudbot` + `kali`
nutzen `network_mode: service:nordvpn` (geteilter Netz-Namespace = aller
Traffic durch den VPN-Tunnel, Leak-Schutz).

## Heutiger Ausfall (4-stufige Kette, alle belegt)
1. `nordvpnd`-Daemon im nordvpn-Container abgestürzt; entrypoint.sh überwachte
   nur die *Verbindung*, nie den *Daemon* → Endlos-Reconnect mit
   "couldn't reach System Daemon".
2. Stale PID/Socket-Lockfiles im persistenten Volume blockten Daemon-Neustart;
   `docker restart` allein löste es nicht.
3. DNS-Setzung scheiterte (kein resolvectl/resolvconf/nmcli im Image).
4. Cloudbot hing nach nordvpn-Neustart am toten Netz-Namespace
   ("Network is unreachable" zu allem) → musste manuell neu gestartet werden.

## Synology-Limit (wichtig für Bewertung)
NordVPN-Killswitch ist NICHT aktivierbar: Kernelmodul `xt_comment` fehlt,
`firewall on` schlägt fehl. Leak-Schutz beruht allein auf network_mode +
IPv6-Disable. `firewall off` ist daher bewusst, kein Fehler.

## Die 3 Änderungen (zu reviewen)

### 1. nordvpn/entrypoint.sh (komplett neu geschrieben)
- `ensure_daemon()`: prüft Daemon-Leben (pgrep) + Erreichbarkeit (nordvpn status);
  startet bei Bedarf neu nach Lockfile-Cleanup, wartet bis zu 30s auf Socket.
- `clean_stale_locks()`: entfernt stale PID/Socket vor jedem Daemon-Start.
- `ensure_login()` idempotent; `apply_settings()` setzt explizit Nord-DNS.
- Watchdog (60s): erst Daemon sicherstellen, dann Login, dann Verbindung;
  bei erfolgreichem Reconnect Marker `/tmp/vpn_reconnected`.
- `set -u` aktiv.

### 2. cloudbot/bot.py (Konnektivitäts-Wächter ergänzt)
- `_connectivity_ok()`: DNS-Auflösung + TCP-Connect:443 zu api.telegram.org.
- `_connectivity_watchdog()`: alle 60s; nach 3 Fehlschlägen in Folge
  `os._exit(1)` → Docker `restart: unless-stopped` bindet frischen Namespace.
- Eingebunden via `post_init` + `app.create_task`. PTB 21.6 verifiziert
  (create_task + post_init existieren).

### 3. docker-compose.yml (healthcheck gehärtet)
- Alt: `curl ifconfig.me` (bewies nur Internet; war heute fälschlich grün).
- Neu: `nordvpn status | grep -q Connected` (echter Tunnel-Status).

## Review-Fokus
- Korrektheit der Daemon-Supervision (Race-Conditions? mehrere nordvpnd?).
- Ist `os._exit(1)` im Bot die richtige Wahl (vs. sys.exit / SystemExit)?
- Watchdog-Schwelle 3×60s sinnvoll gegen Flapping?
- Kann der gehärtete healthcheck zu einem Deadlock führen (Bot startet nie,
  weil nordvpn nie healthy)? Edge-Case beim allerersten Start (start_period).
- Security: Kein Leak-Pfad eingeführt? DNS bleibt im Tunnel?
- `set -u` + ungebundene Variablen (NORDVPN_TOKEN)?
- Bash-Robustheit (pgrep -x verfügbar im ubuntu:22.04-Image?).
