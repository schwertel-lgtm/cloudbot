FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# ============================================
# KOMPLETTES PENTEST / FORENSIK / SE ARSENAL
# ============================================

# Basis + Reconnaissance + Web + Exploitation + Passwords
RUN apt update && \
    apt install -y --no-install-recommends \
    kali-linux-headless \
    exploitdb \
    wordlists \
    seclists \
    # --- Reconnaissance / OSINT ---
    amass \
    subfinder \
    httpx-toolkit \
    nuclei \
    whatweb \
    wafw00f \
    dnsrecon \
    fierce \
    theharvester \
    recon-ng \
    enum4linux \
    nbtscan \
    onesixtyone \
    snmpcheck \
    # --- Web Application Testing ---
    nikto \
    dirb \
    gobuster \
    wpscan \
    sqlmap \
    commix \
    # --- Exploitation ---
    metasploit-framework \
    # --- Password / Brute Force ---
    hydra \
    john \
    hashcat \
    medusa \
    crunch \
    cewl \
    hashid \
    hash-identifier \
    crackmapexec \
    # --- Wireless ---
    aircrack-ng \
    wifite \
    kismet \
    fern-wifi-cracker \
    # --- Sniffing / MITM ---
    wireshark-common \
    tcpdump \
    ettercap-common \
    bettercap \
    responder \
    mitmproxy \
    # --- Social Engineering ---
    set \
    beef-xss \
    # --- Forensik ---
    autopsy \
    sleuthkit \
    binwalk \
    foremost \
    scalpel \
    bulk-extractor \
    libimage-exiftool-perl \
    steghide \
    yara \
    clamav \
    chkrootkit \
    rkhunter \
    # --- Reverse Engineering ---
    ghidra \
    radare2 \
    gdb \
    # --- Active Directory / Windows ---
    bloodhound \
    smbclient \
    smbmap \
    evil-winrm \
    # --- Tunneling / Pivoting ---
    chisel \
    proxychains4 \
    sshuttle \
    tor \
    # --- VoIP ---
    sipvicious \
    # --- Reporting ---
    cherrytree \
    pipal \
    # --- Sonstiges ---
    python3-pip \
    python3-venv \
    git \
    wget \
    curl \
    vim \
    jq \
    net-tools \
    iputils-ping \
    && apt clean && \
    rm -rf /var/lib/apt/lists/*

# Python-basierte Pentest-Tools
RUN pip3 install --no-cache-dir --break-system-packages \
    shodan \
    censys \
    python-whois \
    dnspython \
    requests \
    beautifulsoup4 \
    scapy \
    impacket \
    sslyze \
    pwntools \
    volatility3 \
    stegcracker \
    search-that-hash \
    name-that-hash \
    updog \
    dirsearch \
    droopescan \
    wfuzz \
    arjun \
    ldapdomaindump \
    gophish

# Verzeichnisse fuer Ergebnisse
RUN mkdir -p /root/data/scans /root/data/reports /root/data/loot /root/data/evidence

WORKDIR /root

CMD ["/bin/bash"]
