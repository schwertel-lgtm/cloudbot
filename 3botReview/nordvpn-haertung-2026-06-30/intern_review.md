# code-reviewer-intern Review — NordVPN-Ausfall-Haertung

**Datum:** 2026-06-30
**Branch:** (Working-Tree, uncommitted)
**Commit (spaeter):** pending
**Scope:** Daemon-Supervision (entrypoint.sh neu), Konnektivitaets-Waechter (bot.py),
gehaerteter Tunnel-Healthcheck (docker-compose.yml). Netzwerk-/leak-kritisch.

## MUSS (blockiert Commit)

- **nordvpn/Dockerfile — `procps` fehlt -> pgrep/pkill schlagen still fehl.**
  Der neue `entrypoint.sh` nutzt `pgrep -x nordvpnd` (Z.37) und `pkill -9 nordvpnd`
  (Z.52). Beide kommen aus dem Paket `procps`, das im `ubuntu:22.04`-Minimal-Image
  NICHT vorhanden ist (apt-Liste im Dockerfile installiert nur curl/ca-certificates/
  iproute2/iptables/gnupg). Folge: `daemon_alive()` ruft ein nicht-existentes Binary
  auf -> `pgrep` gibt 127 zurueck -> `daemon_alive` ist IMMER false. Wegen `set -u`
  ist das zwar kein Abbruch (Returncode wird in if/&& gelesen), aber `ensure_daemon`
  glaubt bei jedem Watchdog-Lauf, der Daemon sei tot, und feuert `pkill -9` (auch nicht
  vorhanden) + startet einen ZWEITEN `nordvpnd &`. Das ist exakt die im Fokus genannte
  "mehrere parallele nordvpnd"-Race. **Fix:** `procps` in die apt-install-Zeile des
  Dockerfile aufnehmen. Danach unbedingt einen Build+Lauf verifizieren.

- **nordvpn/entrypoint.sh — Allowlist-Regression (LAN + Docker-Bridge verloren).**
  Der ALTE entrypoint setzte `nordvpn allowlist add subnet 192.168.178.0/24` und
  `172.16.0.0/12` (mit whitelist-Fallback). Beide Zeilen sind im neuen `apply_settings()`
  ERSATZLOS entfallen. `172.16.0.0/12` deckt den Docker-Bridge-Bereich ab — der Bot
  spricht ueber `/var/run/docker.sock` zwar lokal, aber LAN-Zugriff (192.168.178.0/24)
  und Bridge-Routen koennen nach Tunnel-Aufbau wegfallen. Das ist ein Scope-Drift im
  "komplett neu geschrieben" und potenziell ein neuer Funktionsverlust, nicht nur
  Haertung. **Fix:** beide `allowlist add subnet`-Zeilen (mit whitelist-Fallback fuer
  aeltere CLI) in `apply_settings()` uebernehmen. Falls bewusst entfernt: im
  Kommentar begruenden.

## SHOULD (vor Merge fixen)

- **entrypoint.sh — `nordvpnd`-Doppelstart bei langsamem Daemon.** Selbst mit procps:
  Wenn der Daemon lebt (`daemon_alive` true), aber der Socket nach Absturz noch nicht
  antwortet (`daemon_reachable` false), geht `ensure_daemon` in den pkill+restart-Pfad
  und killt den ggf. gerade hochfahrenden Daemon. Akzeptabel (pkill raeumt vorher auf),
  aber der `pkill -9` + sofortiges `clean_stale_locks` ohne Warte-auf-Tod-Schleife kann
  die `.sock`/`.pid` loeschen, bevor der sterbende Prozess sie selbst aufraeumt -> neuer
  Daemon legt sie neu an, ok. Empfehlung: nach `pkill -9` mit kurzer pgrep-Schleife auf
  tatsaechlichen Prozess-Tod warten (statt blindem `sleep 2`), bevor neu gestartet wird.

- **docker-compose.yml — Healthcheck-Deadlock bei dauerhaftem Tunnel-Fail moeglich.**
  `kali`/`cloudbot` sind via `condition: service_healthy` gegated. Kommt der Tunnel
  nach NAS-Reboot nie auf "Connected" (z.B. NordVPN-Wartung, Token abgelaufen), starten
  beide NIE — der Bot kann sich dann auch nicht via Telegram melden. Das war im alten
  `curl`-Check unbeabsichtigt "robuster" (immer gruen). Trade-off ist gewollt
  (Leak-Schutz > Verfuegbarkeit), aber dokumentieren und idealerweise Telegram-Alarm
  ueber einen NICHT-gegateten Pfad erwaegen (Out-of-Scope fuer heute). Mindestens als
  bekannte Konsequenz in den Commit-Body.

- **bot.py — `socket.create_connection` Timeout 10s, aber DNS (`gethostbyname`) ohne
  Timeout.** `asyncio.to_thread` haelt den Event-Loop frei (korrekt — der Loop blockiert
  NICHT), aber der Worker-Thread kann bei totem Namespace lange in `getaddrinfo`
  haengen (glibc-Default bis ~ Sekunden je nach resolv.conf). Bei `_WATCHDOG_INTERVAL=60`
  unkritisch, aber im Worst-Case ueberlappen sich Checks nicht (sequenziell in der
  while-Schleife), nur die 60s-Kadenz dehnt sich. Akzeptabel; optional `gethostbyname`
  durch `getaddrinfo` mit eigenem Thread-Timeout-Guard ersetzen. Kein Blocker.

## CAN (nice-to-have)

- **entrypoint.sh — `nordvpnd`-Start ohne vollen Pfad.** Funktioniert (alter entrypoint
  tat dasselbe, PATH greift), aber `/usr/sbin/nordvpnd` explizit waere robuster gegen
  PATH-Drift in kuenftigen Base-Images.
- **bot.py — `_WATCHDOG_PROBE_HOST` hartkodiert auf api.telegram.org.** Single Probe;
  ein Telegram-seitiger Ausfall (sehr selten) wuerde als Namespace-Verlust fehlgedeutet
  und einen unnoetigen Bot-Neustart ausloesen. Tolerierbar bei 3x60s-Schwelle. Optional
  zweiter Fallback-Host.
- **RECONNECT_MARKER `/tmp/vpn_reconnected` wird gesetzt, aber von niemandem gelesen.**
  Der Bot reagiert auf eigenen Konnektivitaets-Check, nicht auf den Marker (geteilter
  Namespace teilt NICHT das Filesystem). Toter Marker — entweder Cross-Container-Pfad
  klaeren oder Kommentar/Code entfernen, damit Future-Claude nicht nach dem Leser sucht.

## False-Positive-Kandidaten (NICHT fixen)

- **`nordvpnd &` als nackter Hintergrund-Start** ist KEIN neuer Defekt — der alte,
  funktionierende entrypoint nutzte identisch `nordvpnd &`. Nicht als Regression werten.
- **`firewall off` / kein Killswitch** ist bewusst (Synology xt_comment-Limit, im Header
  dokumentiert). Externe Bots (insb. Llama) werden hier "Killswitch fehlt = Leak"
  melden — das ist auf dieser NAS technisch nicht aktivierbar, Leak-Schutz laeuft ueber
  network_mode + IPv6-disable. FP.
- **`os._exit(1)` statt `sys.exit`** ist hier KORREKT: `sys.exit`/`raise SystemExit` aus
  einer asyncio-Task wird vom Loop gefangen und beendet nur die Task, nicht den Prozess
  -> Docker-Restart triggert nicht. `os._exit(1)` umgeht Cleanup hart und beendet den
  Prozess -> `restart: unless-stopped` bindet frischen Namespace. Genau gewollt. Kein
  Finding.
- **`post_init` + `app.create_task`** ist in PTB 21.6 korrekt (create_task an die
  Application haengt die Task an den laufenden Loop, post_init laeuft nach Loop-Start).
  Sauber. Kein Finding.
- **audit_log.py `propagate=False`** (im selben Commit): saubere Aenderung gegen
  Log-Duplizierung, ASCII-Kommentar mit Begruendung — out of review-scope, kein Finding.

## Konsistenz-Hinweise (Code-Stil)

- bot.py: Kommentar-Dichte, ASCII-Umlaut-Vermeidung, Logging-Muster und der bestehende
  TokenScrubFilter werden respektiert. `_connectivity_watchdog` loggt sauber via `logger`.
  Stil GRUEN.
- entrypoint.sh: `log()`-Helfer + Block-Kommentare konsistent, ASCII-safe, `set -u`
  korrekt (alle Variablen mit Defaults bzw. NORDVPN_TOKEN aus .env vorausgesetzt —
  bei fehlendem Token bricht `set -u` in ensure_login ab; akzeptabel, da .env Pflicht ist).

## Fazit: GELB

Committebar nach Fix der 2 MUSS-Findings (procps-Install + Allowlist-Regression) — ohne
procps erzeugt die Supervision selbst die Doppel-Daemon-Race, die sie verhindern soll.
