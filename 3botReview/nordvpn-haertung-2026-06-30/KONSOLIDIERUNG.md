# §10 Cross-Review — Konsolidierung NordVPN-Härtung (2026-06-30)

3 Bots: code-reviewer-intern (GELB, 2 MUSS/3 SHOULD), Llama-4/NVIDIA,
GPT-5 (1. Lauf nur compose wg. API-Disconnects, Retry für entrypoint.sh+bot.py).

## ✅ EINGEARBEITET

### MUSS
1. **procps explizit ins Dockerfile** (intern). `pgrep`/`pkill` waren nur
   transitiv da (am Container verifiziert vorhanden) — explizit deklariert,
   robust gegen Paket-Drift. Sonst wäre daemon_alive() bei Wegfall permanent
   false → Mehrfach-Daemon-Race.
2. **Allowlist-Regression** (intern). `192.168.178.0/24` + `172.16.0.0/12`
   aus dem Alt-Skript fehlten in apply_settings() → wieder eingebaut
   (LAN/Bridge-Erreichbarkeit nach Tunnel-Aufbau).
3. **`Connected` matcht `Disconnected`** (GPT-5, der schärfste Befund).
   `grep "Connected"` matcht "Disconnected" als Substring → Watchdog hätte
   tote Verbindung für verbunden gehalten, nie reconnectet. Fix: is_connected()
   UND healthcheck auf `^Status: Connected` + LC_ALL=C. Status-Format am
   Container verifiziert.
4. **NORDVPN_TOKEN unbound unter set -u** (GPT-5+intern). Early-fail-Guard
   mit klarer Meldung statt kryptischem "unbound variable".

### SHOULD
5. **PID-bewusster Lock-Cleanup** (GPT-5+NVIDIA). clean_stale_locks() prüft
   jetzt kill -0 — löscht PID-Datei nur wenn Prozess tot. Schützt gesunden
   Daemon.
6. **pkill-Warte-auf-Tod** (intern). ensure_daemon() wartet deterministisch
   (max 10s) auf Prozess-Ende vor Neustart → Doppelstart-Schutz.
7. **Healthcheck-Intervalle** (GPT-5). interval 30s/retries 3/start_period 90s
   (vorher 60/3/45) — schnellere Erkennung, aber genug Boot-Zeit gegen
   service_healthy-Deadlock.

## 🔵 GEPRÜFTE FALSE-POSITIVES (bewusst NICHT gefixt)

- **os._exit → sys.exit** (NVIDIA 2× KRITISCH, GPT-5 erkennt selbst
  "beabsichtigt"). FP: sys.exit wirft nur SystemExit in der asyncio-Task,
  beendet den Prozess NICHT → kein Docker-Restart. os._exit(1) ist hier
  korrekt und dokumentiert. Intern bestätigt es als FP.
- **`build.network: host` falsch platziert** (NVIDIA KRITISCH). FP: gültige
  Compose-Syntax (Build-Netzwerk), Bestandscode.
- **Hartkodierter Token** (NVIDIA). FP: kommt aus ${NORDVPN_TOKEN} (Env),
  nicht hartkodiert.

## 🟠 OUT OF SCOPE — Security-Härtungs-Backlog (NICHT in diesem Commit)

Trigger-Pfad-Check: Diese Findings betreffen Bestandscode, NICHT die
Härtungs-Änderung (entrypoint.sh-Rewrite + bot.py-Wächter + Dockerfile +
healthcheck). Real und wertvoll, aber separater Scope — sie hier zu mischen
wäre Scope-Creep. Festgehalten für eine dedizierte Security-Runde:

- **Docker-Socket-Mount = Root-Host-Zugriff** (GPT-5 KRITISCH). Der Bot
  braucht den Socket (cmd_vpn/cmd_restart/cmd_exec steuern Container) — by
  design. Optionen: docker-socket-proxy mit Endpoint-Whitelist.
- **kali NET_ADMIN im VPN-Namespace** (GPT-5 KRITISCH). kali kann theoretisch
  Routing/iptables ändern → VPN umgehen. Prüfen ob NET_ADMIN für kali
  wirklich nötig.
- **Shell-Injection cmd_download/cmd_files** (GPT-5). Pfad wird in `bash -c`
  interpoliert. exec_run mit Argument-Liste statt Shell nutzen. Bestandscode.
- **_already_processed Race** (GPT-5). Globales set/list ohne asyncio.Lock.
  PTB-Handler aber faktisch sequenziell im Loop → niedrige Wahrscheinlichkeit.
- **docker.exec_run-Result-Robustheit** (GPT-5). result.output[0]/[1]-Annahme
  versionsabhängig.
- **TokenScrubFilter in-place + Handler-Timing** (GPT-5).
- **feste DNS 8.8.8.8/1.1.1.1 im nordvpn dns:-Block** (GPT-5). Bootstrap-DNS
  vor Tunnel; Leak-Vektor-Prüfung. VORSICHT: Änderung könnte Daemon-Boot
  (Auflösung der Nord-Server) brechen — nur mit Test ändern.
- **Container-Hardening** (GPT-5): user/read_only/no-new-privileges/cap_drop.

→ Eingetragen als eigener Punkt in VaultCal OFFENE-PUNKTE.md ⚙️.

## Validation-Pass
Kein Skip (Verdict war GELB mit MUSS). Alle MUSS+SHOULD eingearbeitet,
Syntax re-verifiziert (bash -n / py_compile / YAML alle OK). Deploy-bereit.

## 🔴 DEPLOY-BEFUND (nach dem Cross-Review entdeckt, 2026-06-30)

Der `compose up -d`-Deploy schlug zunaechst fehl (nordvpn unhealthy). Per
systematic-debugging isoliert: **NICHT der Code, sondern eine ungewollte
NordVPN-Version-Aktualisierung.** Der Image-Rebuild zog `nordvpn` ohne
Versionspin -> 5.1.0 -> braucht `nft` -> Synology-Kernel hat kein nf_tables
-> Connect haengt ewig. 4.6.0 (iptables-legacy) verbindet sauber.

Zusaetzliche Aenderungen (ueber den Review hinaus, gleiche Datei-Zone):
- **Dockerfile: `nordvpn=4.6.0` gepinnt** (+ ausfuehrlicher Warn-Kommentar).
- **Dockerfile: `procps` + `build.network: host` fuer nordvpn-Build**
  (Build-DNS-Problem im Bridge-Netz).
- **entrypoint.sh: cipher-Fehler-Erkennung** -> Config-Reset bei
  Versionswechsel-Inkompatibilitaet.
- **entrypoint.sh: `nset()` Timeout-Wrapper** fuer Settings-Calls
  (Defense-in-Depth gegen haengende CLI).
- **healthcheck: `^Status: Connected` + LC_ALL=C** (Substring-MUSS) +
  start_period 60s.

Verifiziert: `compose up -d` -> nordvpn AUTOMATISCH healthy nach 31s ->
cloudbot+kali gestartet -> E2E gruen (VPN-IP 64.238.204.99, DNS ok, Telegram
HTTP 200, Anthropic erreichbar, Wächter aktiv). Detail:
cloudbot-Pool `reference_nordvpn_ausfall_diagnose.md` (Versions-Befund oben).
