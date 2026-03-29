#!/bin/bash

# NordVPN Daemon starten
mkdir -p /var/lib/nordvpn /var/run/nordvpn
nordvpnd &
sleep 8

echo "=== NordVPN Login ==="
# 'n' beantworten fuer Analytics, dann Token-Login
printf 'n\n' | nordvpn login --token "${NORDVPN_TOKEN}" 2>&1
sleep 3

# Pruefen ob Login erfolgreich
nordvpn account 2>&1 || {
    echo "Login erneut versuchen..."
    printf 'n\n' | nordvpn login --token "${NORDVPN_TOKEN}" 2>&1
    sleep 3
}

echo "=== NordVPN Einstellungen ==="
nordvpn set technology NordLynx 2>&1 || true
nordvpn set firewall off 2>&1 || true
nordvpn set lan-discovery enable 2>&1 || true

echo "=== Whitelist ==="
nordvpn allowlist add subnet 192.168.178.0/24 2>&1 || nordvpn whitelist add subnet 192.168.178.0/24 2>&1 || true
nordvpn allowlist add subnet 172.16.0.0/12 2>&1 || nordvpn whitelist add subnet 172.16.0.0/12 2>&1 || true

echo "=== Verbinde mit ${NORDVPN_COUNTRY:-Netherlands} ==="
nordvpn connect "${NORDVPN_COUNTRY:-Netherlands}" 2>&1

sleep 5

if nordvpn status 2>/dev/null | grep -q "Connected"; then
    echo "=== VPN verbunden, aktiviere Killswitch ==="
    nordvpn set killswitch on 2>&1 || true
fi

echo "=== Status ==="
nordvpn status 2>&1

echo "=== NordVPN laeuft ==="

# Am Leben halten
while true; do
    sleep 300
    if ! nordvpn status 2>/dev/null | grep -q "Connected"; then
        echo "$(date): VPN getrennt, verbinde neu..."
        nordvpn connect "${NORDVPN_COUNTRY:-Netherlands}" 2>/dev/null || true
    fi
done
