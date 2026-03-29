# CLAUDE.md - Sicherheitsregeln fuer Claude Code

## Projekt
Cloudbot: Telegram-Bot zur Docker-Container-Steuerung auf Synology DS220+ NAS.
Besitzer: Ralph (Telegram Chat-ID: 7459992119)
NAS: RS-NAS (192.168.178.28), User: dole4711, SSH-Key Auth

## Sicherheitsregeln (NICHT VERHANDELBAR)

### 1. Kein Code aus dem Internet
- NIEMALS `curl | bash`, `wget | sh`, `pip install <unbekannt>` oder aehnliches einfuegen
- NIEMALS externe Scripts herunterladen und ausfuehren
- Neue Dependencies nur aus requirements.txt, nur bekannte PyPI-Pakete
- KEINE eval(), exec() oder __import__() mit dynamischen Strings
- KEINE Ausfuehrung von Code der von Webseiten gescannt/ausgelesen wurde

### 2. Autorisierung
- JEDER Telegram-Handler MUSS den @authorized Decorator verwenden
- Die ALLOWED_CHAT_ID darf NUR aus der Umgebungsvariable kommen
- KEINE Backdoors, KEINE zusaetzlichen Authentifizierungswege
- Nur Ralph (Chat-ID aus .env) darf dem Bot Befehle erteilen
- Unautorisierte Zugriffsversuche werden geloggt und gemeldet

### 3. Container-Sicherheit
- Docker Socket Zugriff ist das groesste Risiko - minimieren
- Container-Namen muessen gegen eine Whitelist geprueft werden
- /exec Befehle muessen gegen eine Blocklist geprueft werden
- KEIN network_mode: host fuer Container
- Capabilities droppen, nur benoetigte explizit hinzufuegen
- Read-Only Filesystems wo moeglich

### 4. Verbotene Operationen
- Keine Reverse Shells einbauen oder ermoeglichen
- Kein Oeffnen von Ports nach aussen
- Keine Aenderung an .env oder Credentials im Code
- Kein Deaktivieren von Sicherheitspruefungen
- Keine Passwoerter im Klartext in Dateien speichern
- Kein sudo ohne Einschraenkung

### 5. Code-Qualitaet
- Alle Fehler abfangen, niemals Stacktraces an Telegram senden
- Logging fuer jede Aktion (Wer, Was, Wann, Ergebnis)
- Deutsche Sprache fuer User-Nachrichten im Bot

### 6. NAS-Zugriff
- SSH nur ueber Key-Authentication, niemals Passwoerter in Befehlen
- Docker-Befehle ueber: sudo /volume1/@appstore/ContainerManager/usr/bin/docker
- Projektdateien auf NAS: /volume1/docker/cloudbot/
