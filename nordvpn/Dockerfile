FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# procps liefert pgrep/pkill — die Daemon-Supervision in entrypoint.sh
# (daemon_alive / ensure_daemon, seit Haertung 2026-06-30) ist darauf
# angewiesen. Explizit deklariert, NICHT auf transitive Abhaengigkeit
# verlassen: faellt procps bei einem Paket-Update weg, waere daemon_alive
# permanent false -> Mehrfach-Daemon-Race.
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    iproute2 \
    iptables \
    gnupg \
    procps \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
    && rm -rf /var/lib/apt/lists/*

# NordVPN Repository manuell hinzufuegen.
#
# VERSION GEPINNT AUF 4.6.0 (Belegfall 2026-06-30, KRITISCH):
# NordVPN 5.0.0+ ist auf dem Synology-Kernel NICHT connect-faehig. Diese
# Versionen bauen ihre Firewall-/Routing-Regeln ueber `nft` (nftables) auf,
# aber der Synology-Kernel hat KEIN nf_tables-Modul (`nft add ...` ->
# "Operation not supported"). Folge: Tunnel haengt ewig bei "Connecting",
# `set firewall off` ist wirkungslos (auch das laeuft ueber nft). 4.6.0
# nutzt iptables-legacy (vom Kernel unterstuetzt) + Firewall ist
# abschaltbar -> verbindet sauber. OHNE Pin zieht `apt-get install nordvpn`
# immer die neueste (kaputte) Version. Vor einem Upgrade-Versuch zwingend
# pruefen, ob der Kernel inzwischen nf_tables hat (`nft add table inet t`).
RUN curl -sSf https://repo.nordvpn.com/gpg/nordvpn_public.asc | gpg --dearmor -o /usr/share/keyrings/nordvpn.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/nordvpn.gpg] https://repo.nordvpn.com/deb/nordvpn/debian stable main" > /etc/apt/sources.list.d/nordvpn.list && \
    apt-get update && \
    apt-get install -y --allow-downgrades nordvpn=4.6.0 && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
