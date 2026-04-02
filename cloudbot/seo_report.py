"""
PDF-Bericht-Generator fuer SEO-Analysen.
Erstellt professionelle, kundenfreundliche PDF-Berichte.
"""

import os
import re
from datetime import datetime
from fpdf import FPDF


class SEOReport(FPDF):
    """Professioneller SEO-Bericht als PDF."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "SEO-Analyse | Cloudbot Security Services", align="R")
        self.ln(4)
        self.set_draw_color(0, 120, 200)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 10, f"Seite {self.page_no()}/{{nb}}", align="C")

    def _add_title_page(self, domain, date_str):
        """Erstellt die Titelseite."""
        self.add_page()
        self.ln(40)

        # Titel
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(0, 80, 160)
        self.cell(0, 15, "SEO-Analyse", align="C")
        self.ln(18)

        # Domain
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(40, 40, 40)
        self.cell(0, 12, domain, align="C")
        self.ln(20)

        # Trennlinie
        self.set_draw_color(0, 120, 200)
        self.set_line_width(1)
        self.line(60, self.get_y(), 150, self.get_y())
        self.ln(20)

        # Datum
        self.set_font("Helvetica", "", 14)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Erstellt am: {date_str}", align="C")
        self.ln(10)

        # Auftraggeber
        self.cell(0, 10, "Auftraggeber: Ralph", align="C")
        self.ln(30)

        # Hinweis
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(130, 130, 130)
        self.multi_cell(0, 5,
            "Dieser Bericht wurde automatisch erstellt und dient als "
            "Grundlage fuer die Optimierung der Suchmaschinenplatzierung. "
            "Alle Empfehlungen sind nach Prioritaet sortiert.",
            align="C")

    def _add_section(self, title):
        """Fuegt eine Abschnittsueberschrift hinzu."""
        if self.get_y() > 250:
            self.add_page()
        self.ln(4)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(0, 80, 160)
        self.cell(0, 10, self._safe(title))
        self.ln(8)
        self.set_draw_color(0, 120, 200)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 120, self.get_y())
        self.ln(4)

    def _add_subsection(self, title):
        """Fuegt eine Unterueberschrift hinzu."""
        if self.get_y() > 260:
            self.add_page()
        self.ln(2)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, self._safe(title))
        self.ln(6)

    @staticmethod
    def _safe(text):
        """Entfernt alle Zeichen die fpdf/Helvetica nicht darstellen kann."""
        replacements = {
            "\u2714": "[OK]", "\u2705": "[OK]", "\u2611": "[OK]",
            "\u2716": "[X]", "\u274c": "[X]", "\u2612": "[X]",
            "\u26a0": "[!]", "\u26a0\ufe0f": "[!]",
            "\u2b50": "*", "\u2b50\ufe0f": "*",
            "\u2022": "-", "\u25cf": "-", "\u25cb": "-",
            "\u2013": "-", "\u2014": "-", "\u2015": "-",
            "\u201e": "\"", "\u201c": "\"", "\u201d": "\"",
            "\u2018": "'", "\u2019": "'",
            "\u2192": "->", "\u2190": "<-",
            "\u2713": "[OK]", "\u2717": "[X]",
            "\U0001f534": "[!!]", "\U0001f7e0": "[!]",
            "\U0001f7e2": "[OK]", "\U0001f7e1": "[!]",
            "\U0001f680": "", "\U0001f4ca": "", "\U0001f4a1": "",
            "\ufe0f": "",
        }
        for char, repl in replacements.items():
            text = text.replace(char, repl)
        # Alle verbleibenden Non-Latin1 Zeichen entfernen
        result = []
        for ch in text:
            try:
                ch.encode("latin-1")
                result.append(ch)
            except UnicodeEncodeError:
                pass
        return "".join(result)

    def _add_text(self, text):
        """Fuegt normalen Text hinzu."""
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        text = self._safe(text)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def _add_bullet(self, text, color="black"):
        """Fuegt einen Aufzaehlungspunkt hinzu."""
        if color == "red":
            self.set_text_color(200, 0, 0)
        elif color == "green":
            self.set_text_color(0, 150, 0)
        elif color == "orange":
            self.set_text_color(220, 140, 0)
        else:
            self.set_text_color(40, 40, 40)
        self.set_font("Helvetica", "", 10)
        text = self._safe(text)
        self.cell(8, 5, "-")
        self.multi_cell(0, 5, text)
        self.ln(1)
        self.set_text_color(40, 40, 40)

    def _add_code_block(self, code):
        """Fuegt einen Code-Block hinzu."""
        self.set_font("Courier", "", 9)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(40, 40, 40)
        for line in code.strip().split("\n"):
            self.cell(0, 5, "  " + self._safe(line), fill=True)
            self.ln(4)
        self.ln(3)
        self.set_font("Helvetica", "", 10)


def _clean_markdown(text):
    """Entfernt Markdown-Formatierung und Emojis."""
    # Emojis entfernen
    emoji_pattern = re.compile(
        "[\U0001f300-\U0001f9ff\U0001fa00-\U0001faff"
        "\u2600-\u27bf\u2300-\u23ff\u2b50\u26a0"
        "\U0001f600-\U0001f64f]+", flags=re.UNICODE)
    text = emoji_pattern.sub("", text)
    # Markdown bold/italic
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"__(.+?)__", r"\1", text)
    # Markdown headers -> plain text
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)
    return text.strip()


def generate_seo_pdf(report_text, domain=None):
    """
    Generiert ein professionelles SEO-PDF aus dem Berichtstext.
    Gibt den Dateipfad zum PDF zurueck.
    """
    # Domain aus Text extrahieren falls nicht angegeben
    if not domain:
        match = re.search(r"(?:analyse|bericht)[:\s]+(\S+\.\S+)", report_text, re.I)
        domain = match.group(1) if match else "Unbekannte Domain"

    # Domain bereinigen
    domain = domain.strip().strip("*").strip(":")

    date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
    clean_text = _clean_markdown(report_text)

    pdf = SEOReport()
    pdf.alias_nb_pages()

    # Titelseite
    pdf._add_title_page(domain, date_str)

    # Inhalt parsen und formatieren
    pdf.add_page()
    lines = clean_text.split("\n")
    in_code_block = False
    code_buffer = []

    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        # Code-Block Erkennung
        if stripped.startswith("```"):
            if in_code_block:
                pdf._add_code_block("\n".join(code_buffer))
                code_buffer = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            code_buffer.append(stripped)
            continue

        # Sektionsueberschriften erkennen
        upper = stripped.upper()
        if any(keyword in upper for keyword in [
            "ZUSAMMENFASSUNG", "ERGEBNISSE", "PROBLEME",
            "VERBESSERUNGEN", "QUICK WINS", "SOFORT UMSETZBAR",
            "META-TAGS", "TECHNISCH", "PERFORMANCE",
            "DOMAIN", "CRAWLING", "MOBILE", "CONTENT",
            "SSL", "SICHERHEIT", "HEADING", "HTML",
        ]) and len(stripped) < 80 and not stripped.startswith("-"):
            # Nummerierung entfernen
            clean_title = re.sub(r"^\d+\.\s*", "", stripped)
            pdf._add_section(clean_title)
            continue

        # Aufzaehlungen
        if stripped.startswith(("- ", "* ", "[ ]", "[x]")):
            bullet_text = re.sub(r"^[-*\[\]x ]+", "", stripped).strip()
            if any(w in stripped.upper() for w in ["KRITISCH", "FEHLT", "FEHLEN"]):
                pdf._add_bullet(bullet_text, "red")
            elif any(w in stripped.upper() for w in ["GUT", "OK", "AKTIV", "VORHANDEN"]):
                pdf._add_bullet(bullet_text, "green")
            elif any(w in stripped.upper() for w in ["WARNUNG", "MANGEL", "PROBLEM"]):
                pdf._add_bullet(bullet_text, "orange")
            else:
                pdf._add_bullet(bullet_text)
            continue

        # Normaler Text
        pdf._add_text(stripped)

    # PDF speichern
    filename = f"seo_analyse_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    filepath = os.path.join("/app/logs", filename)
    pdf.output(filepath)
    return filepath
