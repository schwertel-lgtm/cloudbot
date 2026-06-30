#!/bin/bash
#
# NordVPN Entrypoint — gehaertet 2026-06-30 nach Ausfall-Analyse.
#
# Behebt die 4-stufige Ausfall-Kette vom 2026-06-30:
#   1. nordvpnd-Daemon stirbt -> wurde nie ueberwacht (nur die Verbindung).
#   2. stale PID/Socket-Lockfiles blocken den Daemon-Neustart.
#   3. DNS-Setzung scheitert still -> explizit Nord-DNS setzen.
#   4. Cloudbot haengt nach nordvpn-Neustart am toten Namespace
#      -> der Bot-Container prueft selbst seine Konnektivitaet und
#         beendet sich bei Verlust (Docker startet ihn frisch neu).
#         Dieses Skript setzt nur den Reconnect-Marker + loggt sauber.
#
# WICHTIG (Synology-Limit): Der NordVPN-Killswitch ist auf diesem Kernel
# NICHT aktivierbar (xt_comment-Modul fehlt -> `firewall on` schlaegt fehl).
# Der Leak-Schutz beruht daher allein auf der network_mode-Namespace-Bindung
# + IPv6-Disable. Wir setzen `firewall off` bewusst, weil `on` ohnehin
# scheitert und nur Fehler-Rauschen erzeugt.

set -u

# NORDVPN_TOKEN ist Pflicht. Unter `set -u` wuerde ein fehlender Token sonst
# erst spaet als kryptisches "unbound variable" crashen — lieber hier early-fail
# mit klarer Meldung. (Cross-Review-MUSS 2026-06-30: set -u + ungebundene Var.)
if [ -z "${NORDVPN_TOKEN:-}" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [entrypoint] FATAL: NORDVPN_TOKEN nicht gesetzt (env_file .env pruefen). Abbruch." >&2
    exit 2
fi

COUNTRY="${NORDVPN_COUNTRY:-Netherlands}"
NORD_DNS_1="103.86.96.100"
NORD_DNS_2="103.86.99.100"
RECONNECT_MARKER="/tmp/vpn_reconnected"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [entrypoint] $*"; }

# --- stale Lockfiles entfernen (ueberleben im persistenten Volume) ----------
# PID-bewusst: NUR loeschen, wenn der in der PID-Datei genannte Prozess
# wirklich tot ist. Schuetzt einen GESUNDEN Daemon davor, dass ihm seine
# Lockfiles unter den Fuessen weggezogen werden (Cross-Review-SHOULD).
# Wird nur aufgerufen, nachdem ensure_daemon den Daemon als nicht erreichbar
# eingestuft hat — der zusaetzliche kill -0-Check ist Defense-in-Depth.
clean_stale_locks() {
    local f pid
    for f in /run/nordvpn/nordvpnd.pid /var/run/nordvpn/nordvpnd.pid; do
        [ -f "$f" ] || continue
        pid="$(cat "$f" 2>/dev/null || echo '')"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log "PID-Datei $f zeigt auf lebenden Prozess $pid — NICHT entfernt."
            continue
        fi
        rm -f "$f" 2>/dev/null || true
    done
    # Socket-Dateien haben keine PID-Info — entfernen wenn kein Daemon laeuft.
    if ! pgrep -x nordvpnd >/dev/null 2>&1; then
        rm -f /run/nordvpn/nordvpnd.sock /var/run/nordvpn/nordvpnd.sock 2>/dev/null || true
    fi
}

# --- ist der Daemon-Prozess am Leben? ---------------------------------------
daemon_alive() {
    pgrep -x nordvpnd >/dev/null 2>&1
}

# --- ist die CLI mit dem Daemon erreichbar? ---------------------------------
daemon_reachable() {
    # `nordvpn status` antwortet nur, wenn der Daemon-Socket lebt.
    nordvpn status >/dev/null 2>&1
}

# --- Daemon sicherstellen: starten falls tot, auf Erreichbarkeit warten -----
ensure_daemon() {
    if daemon_alive && daemon_reachable; then
        return 0
    fi
    log "Daemon nicht erreichbar — Reste killen, Lockfiles bereinigen, neu starten."
    pkill -9 nordvpnd 2>/dev/null || true
    # Deterministisch auf den Tod des alten Prozesses warten, BEVOR ein neuer
    # startet — sonst Doppelstart-Race (Cross-Review-SHOULD). Max ~10s.
    for _ in $(seq 1 10); do
        pgrep -x nordvpnd >/dev/null 2>&1 || break
        sleep 1
    done
    if pgrep -x nordvpnd >/dev/null 2>&1; then
        log "WARNUNG: alter nordvpnd nach 10s noch am Leben — Neustart trotzdem riskant, ueberspringe."
        return 1
    fi
    clean_stale_locks
    mkdir -p /var/lib/nordvpn /var/run/nordvpn /run/nordvpn
    nordvpnd >/tmp/nordvpnd.log 2>&1 &
    # auf Daemon-Socket warten (max ~30s)
    for i in $(seq 1 30); do
        if daemon_reachable; then
            log "Daemon ist nach ${i}s erreichbar."
            return 0
        fi
        sleep 1
    done
    # Sonderfall (Belegfall 2026-06-30): Wurde die Config von einer ANDEREN
    # NordVPN-Version verschluesselt (z.B. nach Versionswechsel 5.x<->4.6.0),
    # scheitert der Start mit "cipher: message authentication failed" und der
    # Socket erscheint nie. Dann Config EINMAL zuruecksetzen und neu starten.
    if grep -qi "cipher: message authentication failed" /tmp/nordvpnd.log 2>/dev/null; then
        log "Config inkompatibel (cipher-Fehler, Versionswechsel?) — Config-Reset + Daemon-Neustart."
        pkill -9 nordvpnd 2>/dev/null || true
        sleep 2
        rm -rf /var/lib/nordvpn/data /var/lib/nordvpn/conf 2>/dev/null || true
        clean_stale_locks
        nordvpnd >/tmp/nordvpnd.log 2>&1 &
        for i in $(seq 1 30); do
            if daemon_reachable; then
                log "Daemon nach Config-Reset erreichbar (${i}s)."
                return 0
            fi
            sleep 1
        done
    fi
    log "WARNUNG: Daemon nach 30s nicht erreichbar — Log /tmp/nordvpnd.log."
    return 1
}

# --- Login (idempotent) -----------------------------------------------------
ensure_login() {
    if nordvpn account 2>/dev/null | grep -qiE "email|account information"; then
        return 0
    fi
    log "Nicht eingeloggt — Token-Login."
    printf 'n\n' | nordvpn login --token "${NORDVPN_TOKEN}" >/dev/null 2>&1
    sleep 3
    if ! nordvpn account 2>/dev/null | grep -qiE "email|account information"; then
        log "Login-Retry."
        printf 'n\n' | nordvpn login --token "${NORDVPN_TOKEN}" >/dev/null 2>&1
        sleep 3
    fi
}

# --- ein einzelner `nordvpn ...`-Aufruf, gegen Haengen abgesichert ----------
# Defense-in-Depth: Jeder Settings-Call laeuft mit hartem Timeout, damit ein
# haengender CLI-Aufruf nie den gesamten Hochlauf blockiert (-> connect wird
# nie erreicht -> healthcheck unhealthy). Bei 4.6.0 kehren die Calls normal
# zurueck; der Timeout ist Absicherung, kein Normalfall.
nset() {
    timeout 20 nordvpn "$@" >/dev/null 2>&1 \
        || log "nordvpn $* fehlgeschlagen/timeout (uebersprungen)."
}

# --- Basis-Einstellungen (idempotent) ---------------------------------------
apply_settings() {
    nset set technology NordLynx
    # Killswitch braucht Firewall; Firewall scheitert auf Synology (xt_comment).
    # Daher bewusst firewall off — kein Killswitch moeglich, dokumentiert.
    nset set firewall off
    nset set lan-discovery enable
    # LAN + Docker-Bridge allowlisten, damit der geteilte Namespace
    # (cloudbot/kali, SSH zum NAS) nach Tunnel-Aufbau erreichbar bleibt.
    # Bei aktivem lan-discovery lehnt NordVPN private Subnetze ab -> dann
    # ist das LAN ohnehin abgedeckt (deshalb tolerant). Beide CLI-Varianten
    # (allowlist neu / whitelist alt) abfangen.
    for net in 192.168.178.0/24 172.16.0.0/12; do
        timeout 20 nordvpn allowlist add subnet "$net" >/dev/null 2>&1 \
            || timeout 20 nordvpn whitelist add subnet "$net" >/dev/null 2>&1 || true
    done
    # DNS explizit auf Nord-Resolver (bleibt im Tunnel, kein Leak).
    nset set dns "${NORD_DNS_1}" "${NORD_DNS_2}"
}

# --- verbunden? -------------------------------------------------------------
# WICHTIG: praezise verankern. `grep "Connected"` wuerde auch "Disconnected"
# als Substring matchen -> der Watchdog haette eine TOTE Verbindung fuer
# verbunden gehalten und nie reconnectet (Cross-Review-MUSS 2026-06-30).
# LC_ALL=C nagelt die Locale fest, damit das Status-Label stabil bleibt.
is_connected() {
    LC_ALL=C nordvpn status 2>/dev/null | grep -qE '^Status: Connected'
}

connect_vpn() {
    nordvpn connect "${COUNTRY}" >/dev/null 2>&1 || true
}

# === Initial-Setup ==========================================================
log "=== NordVPN Start (gehaertetes entrypoint.sh) ==="
clean_stale_locks
ensure_daemon || log "Daemon-Start beim Boot fehlgeschlagen — Watchdog versucht weiter."
ensure_login
apply_settings

log "=== Verbinde mit ${COUNTRY} ==="
connect_vpn
sleep 5
if is_connected; then
    log "VPN verbunden."
    nordvpn status 2>/dev/null | grep -vE "update|version" | sed 's/^/  /'
else
    log "WARNUNG: Erstverbindung nicht bestaetigt — Watchdog uebernimmt."
fi

log "=== NordVPN laeuft — Watchdog aktiv (alle 60s) ==="

# === Watchdog ===============================================================
# Zwei Ebenen: erst Daemon sicherstellen, dann Verbindung. Bei jedem
# erfolgreichen Reconnect den Marker setzen, damit die Bot-Seite weiss,
# dass der Namespace ggf. neu gebunden werden muss.
while true; do
    sleep 60

    if ! ensure_daemon; then
        continue   # Daemon kam nicht hoch — naechste Runde erneut versuchen
    fi

    # Login kann nach Daemon-Neustart verloren sein
    if ! nordvpn account 2>/dev/null | grep -qiE "email|account information"; then
        ensure_login
        apply_settings
    fi

    if ! is_connected; then
        log "VPN getrennt — reconnect."
        connect_vpn
        sleep 5
        if is_connected; then
            log "Reconnect erfolgreich — Marker gesetzt."
            date '+%s' > "${RECONNECT_MARKER}" 2>/dev/null || true
        else
            log "Reconnect fehlgeschlagen — naechste Runde."
        fi
    fi
done
