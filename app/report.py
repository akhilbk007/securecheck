"""Builds the downloadable PDF report from a scan result.

Everything in a scan result that came from the scanned site (header values,
cookie names, certificate fields) is untrusted. ReportLab paragraphs accept a
small markup language, so every value is escaped before it is placed.
"""
from __future__ import annotations

import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
LEFT = MARGIN + 6            # the page frame adds 6pt of padding inside the margin
WIDTH = PAGE_W - 2 * LEFT
BAND_H = 52 * mm

NAVY = colors.HexColor("#0f2438")
INK = colors.HexColor("#0f2438")
SOFT = colors.HexColor("#52667a")
RULE = colors.HexColor("#d3dce4")
PANEL = colors.HexColor("#f3f6f9")
WHITE = colors.white

RED, AMBER, GREEN, GREY = "#b3232b", "#9a5b00", "#146c43", "#52667a"
STATUS = {  # label, text colour, tint for the card background
    "fail": ("FAIL", RED, "#fbeeee"),
    "warn": ("WARN", AMBER, "#fbf4e6"),
    "info": ("NOTE", GREY, "#f3f6f9"),
    "pass": ("PASS", GREEN, "#edf7f1"),
}
GRADE_COLOR = {"A+": GREEN, "A": GREEN, "B": GREEN, "C": AMBER, "D": AMBER, "F": RED}
ORDER = {"fail": 0, "warn": 1, "info": 2, "pass": 3}

BODY = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8.5, leading=12, textColor=SOFT)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=14, leading=18,
                    spaceBefore=16, spaceAfter=7)
CARD_TITLE = ParagraphStyle("cardtitle", parent=BODY, fontName="Helvetica-Bold", fontSize=10.5, leading=14)
CODE = ParagraphStyle("code", parent=BODY, fontName="Courier", fontSize=8, leading=11)
LABEL = ParagraphStyle("label", parent=SMALL, fontName="Helvetica-Bold", fontSize=7.5, leading=10)
STAT_NUM = ParagraphStyle("statnum", parent=BODY, fontName="Helvetica-Bold", fontSize=20, leading=24,
                          alignment=TA_CENTER)
STAT_LABEL = ParagraphStyle("statlabel", parent=SMALL, alignment=TA_CENTER)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=9, leading=12.5)
CELL_HEAD = ParagraphStyle("cellhead", parent=CELL, fontName="Helvetica-Bold", textColor=SOFT, fontSize=8)
CELL_NUM = ParagraphStyle("cellnum", parent=CELL, alignment=TA_CENTER, fontName="Helvetica-Bold")


def _t(value, limit: int = 900) -> str:
    """Make any value safe to place in a paragraph."""
    text = str(value if value is not None else "")[:limit]
    text = text.encode("latin-1", "replace").decode("latin-1")  # built-in PDF fonts are Latin-1
    text = "".join(ch if ch >= " " or ch == "\n" else " " for ch in text)
    return escape(text)


def _plain(value, limit: int = 120) -> str:
    """Text drawn straight onto the canvas (no markup, so no escaping needed)."""
    text = str(value if value is not None else "")[:limit]
    text = text.encode("latin-1", "replace").decode("latin-1")
    return "".join(ch if ch >= " " else " " for ch in text)


def _break_long(text: str, every: int = 78) -> str:
    """Let long unbroken values (policies, hashes) wrap inside the page."""
    out = []
    for word in text.split(" "):
        while len(word) > every:
            out.append(word[:every])
            word = word[every:]
        out.append(word)
    return " ".join(out)


def _when(iso) -> str:
    try:
        dt = datetime.fromisoformat(str(iso))
        return f"{dt.day} {dt.strftime('%B %Y, %H:%M')} UTC"
    except (ValueError, TypeError):
        return _plain(iso, 40)


def _color(hex_value: str, text: str, bold: bool = True) -> str:
    inner = f"<b>{text}</b>" if bold else text
    return f'<font color="{hex_value}">{inner}</font>'


class _Pages:
    """Page furniture: the title band on page one, a slim header afterwards."""

    def __init__(self, result: dict):
        self.host = _plain(result.get("host"), 80)
        self.url = _plain(result.get("final_url"), 110)
        self.when = _when(result.get("scanned_at"))
        self.grade = _plain(result.get("grade", "?"), 2)
        self.score = int(result.get("score", 0))

    def _footer(self, c, doc):
        c.setFont("Helvetica", 8)
        c.setFillColor(SOFT)
        c.drawString(LEFT, 10 * mm, "SecureCheck is a passive configuration check, not a penetration test.")
        c.drawRightString(PAGE_W - LEFT, 10 * mm, f"Page {doc.page}")

    def first(self, c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, PAGE_H - BAND_H, PAGE_W, BAND_H, stroke=0, fill=1)

        c.setFillColor(colors.HexColor("#9fb4c8"))
        c.setFont("Helvetica-Bold", 9)
        c.drawString(LEFT, PAGE_H - 15 * mm, "SECURECHECK")
        c.setFont("Helvetica", 9)
        c.drawString(LEFT + 27 * mm, PAGE_H - 15 * mm, "Website security report")

        size, room = 26, WIDTH - 46 * mm
        while size > 12 and stringWidth(self.host, "Helvetica-Bold", size) > room:
            size -= 1
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", size)
        c.drawString(LEFT, PAGE_H - 30 * mm, self.host)

        c.setFillColor(colors.HexColor("#c9d6e2"))
        c.setFont("Helvetica", 9.5)
        c.drawString(LEFT, PAGE_H - 38 * mm, f"Scanned {self.when}")
        c.drawString(LEFT, PAGE_H - 43.5 * mm, self.url)

        # Grade badge
        cx, cy, r = PAGE_W - LEFT - 17 * mm, PAGE_H - BAND_H / 2, 17 * mm
        ring = colors.HexColor(GRADE_COLOR.get(self.grade, GREY))
        c.setFillColor(WHITE)
        c.circle(cx, cy, r, stroke=0, fill=1)
        c.setStrokeColor(ring)
        c.setLineWidth(3)
        c.circle(cx, cy, r - 2.2 * mm, stroke=1, fill=0)
        c.setFillColor(ring)
        c.setFont("Helvetica-Bold", 30)
        c.drawCentredString(cx, cy - 2 * mm, self.grade)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(cx, cy - 9 * mm, f"{self.score} / 100")

        self._footer(c, doc)
        c.restoreState()

    def later(self, c, doc):
        c.saveState()
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor(INK)
        c.drawString(LEFT, PAGE_H - 12 * mm, "SecureCheck")
        c.setFont("Helvetica", 8.5)
        c.setFillColor(SOFT)
        c.drawString(LEFT + 21 * mm, PAGE_H - 12 * mm, f"{self.host}, grade {self.grade}")
        c.setStrokeColor(RULE)
        c.setLineWidth(0.6)
        c.line(LEFT, PAGE_H - 14.5 * mm, PAGE_W - LEFT, PAGE_H - 14.5 * mm)
        self._footer(c, doc)
        c.restoreState()


def _stats(result: dict) -> Table:
    counts = result.get("counts", {})
    cells = [
        (str(int(result.get("score", 0))), "Score out of 100", GRADE_COLOR.get(str(result.get("grade")), GREY)),
        (str(int(counts.get("fail", 0))), "To fix", RED),
        (str(int(counts.get("warn", 0))), "To improve", AMBER),
        (str(int(counts.get("pass", 0))), "Passed", GREEN),
    ]
    row = [[Paragraph(_color(color, num), STAT_NUM), Paragraph(label, STAT_LABEL)] for num, label, color in cells]
    gap = 4 * mm
    col = (WIDTH - 3 * gap) / 4
    table = Table([[row[0], "", row[1], "", row[2], "", row[3]]],
                  colWidths=[col, gap, col, gap, col, gap, col])
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]
    for i in (0, 2, 4, 6):
        style.append(("BACKGROUND", (i, 0), (i, 0), PANEL))
        style.append(("ROUNDEDCORNERS", [4, 4, 4, 4]))
    table.setStyle(TableStyle(style))
    return table


def _grid(rows, widths, header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.5, RULE),
             ("LEFTPADDING", (0, 0), (0, -1), 0), ("RIGHTPADDING", (-1, 0), (-1, -1), 0),
             ("TOPPADDING", (0, 0), (-1, -1), 4.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5)]
    if header:
        style.append(("LINEBELOW", (0, 0), (-1, 0), 0.9, INK))
    table.setStyle(TableStyle(style))
    return table


def _controls_text(controls: list) -> str:
    groups: dict[str, list[str]] = {}
    for c in controls[:20]:
        groups.setdefault(str(c.get("framework")), []).append(str(c.get("id")))
    return "; ".join(f"{_t(name, 30)} {_t(', '.join(ids), 60)}" for name, ids in groups.items())


def _cert_strip(result: dict):
    cert = (result.get("tls") or {}).get("certificate") or {}
    days = cert.get("days_left")
    if not isinstance(days, int):
        return None
    when = cert.get("expires_text") or cert.get("expires")
    color = RED if days < 14 else AMBER if days < 30 else GREEN
    if days < 0:
        text = f"<b>The certificate expired on {_t(when, 40)}.</b>"
    else:
        text = (f"<b>Certificate expires on {_t(when, 40)}</b>, in {days} day{'' if days == 1 else 's'}. "
                f"Issued by {_t(cert.get('issuer') or 'an unknown authority', 80)}.")
    strip = Table([["", Paragraph(text, BODY)]], colWidths=[1.6 * mm, WIDTH - 1.6 * mm])
    strip.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor(color)),
                               ("BACKGROUND", (1, 0), (1, 0), PANEL),
                               ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
                               ("LEFTPADDING", (1, 0), (1, 0), 9),
                               ("TOPPADDING", (1, 0), (1, 0), 7), ("BOTTOMPADDING", (1, 0), (1, 0), 7)]))
    return strip


CONTROL_WORD = {"fail": ("GAP", RED), "warn": ("PARTIAL", AMBER), "pass": ("NO GAP", GREEN)}


def _compliance(result: dict) -> list:
    frameworks = [fw for fw in (result.get("compliance") or []) if fw.get("controls")]
    if not frameworks:
        return []
    out = [PageBreak(), Paragraph("Compliance mapping", H2), Paragraph(
        "How the findings in this report relate to common security frameworks. The mapping is "
        "indicative: a web scan sees only part of what each control covers, so use this to decide "
        "where to look. It is not an audit result.", SMALL), Spacer(1, 4)]
    for fw in frameworks:
        counts = fw.get("counts") or {}
        parts = []
        if counts.get("fail"):
            parts.append(_color(RED, f"{int(counts['fail'])} with gaps"))
        if counts.get("warn"):
            parts.append(_color(AMBER, f"{int(counts['warn'])} partial"))
        if counts.get("pass"):
            parts.append(_color(GREEN, f"{int(counts['pass'])} with no gap found"))
        heading = Paragraph(f"<b>{_t(fw.get('framework'), 40)}</b> &nbsp; {', '.join(parts)}",
                            ParagraphStyle("fw", parent=BODY, fontSize=11, leading=15, spaceBefore=10, spaceAfter=4))
        rows = [[Paragraph("Control", CELL_HEAD), Paragraph("Result", CELL_HEAD),
                 Paragraph("Related checks", CELL_HEAD)]]
        for c in fw["controls"]:
            word, color = CONTROL_WORD.get(c.get("status"), ("NOTE", GREY))
            checks = c.get("checks") or []
            gaps = [k for k in checks if k.get("status") != "pass"]
            if gaps:
                related = "; ".join(_t(k.get("title"), 120) for k in gaps[:8])
            else:
                related = _color(GREY, f"{len(checks)} related check{'' if len(checks) == 1 else 's'} passed", bold=False)
            rows.append([Paragraph(f"<b>{_t(c.get('id'), 12)}</b> {_t(c.get('name'), 90)}", CELL),
                         Paragraph(_color(color, word), CELL), Paragraph(related, CELL)])
        table = _grid(rows, [62 * mm, 20 * mm, WIDTH - 82 * mm])
        out.append(KeepTogether([heading, table]) if len(rows) <= 9 else heading)
        if len(rows) > 9:
            out.append(table)
    return out


def _card(f: dict) -> Table:
    label, color, tint = STATUS.get(f.get("status"), STATUS["info"])
    severity = _t(f.get("severity"), 10).capitalize()
    head = f"{_color(color, label)} &nbsp;&nbsp; {_t(f.get('title'), 160)}"
    body = [Paragraph(head, CARD_TITLE)]
    if f.get("status") in ("fail", "warn") and severity:
        body.append(Paragraph(f"{severity} severity", SMALL))
    body += [Spacer(1, 3), Paragraph(_t(f.get("detail")), BODY)]

    if f.get("evidence"):
        seen = Table([[Paragraph("OBSERVED", LABEL)],
                      [Paragraph(_t(_break_long(str(f["evidence"])), 600), CODE)]], colWidths=[WIDTH - 12 * mm])
        seen.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WHITE),
                                  ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                                  ("TOPPADDING", (0, 0), (-1, 0), 4), ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
                                  ("TOPPADDING", (0, 1), (-1, 1), 1), ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
        body += [Spacer(1, 5), seen]

    if f.get("fix") and f.get("status") in ("fail", "warn"):
        body += [Spacer(1, 5), Paragraph("HOW TO FIX", LABEL),
                 Paragraph(_t(_break_long(str(f["fix"]))), BODY)]
    ref = str(f.get("reference") or "")
    if ref.startswith("https://"):
        body += [Spacer(1, 3), Paragraph(f"Further reading: {_t(ref, 200)}", SMALL)]
    controls = _controls_text(f.get("controls") or [])
    if controls:
        body += [Spacer(1, 3), Paragraph(f"<b>Related controls:</b> {controls}", SMALL)]

    card = Table([["", body]], colWidths=[1.6 * mm, WIDTH - 1.6 * mm])
    card.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor(color)),
                              ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(tint)),
                              ("VALIGN", (0, 0), (-1, -1), "TOP"),
                              ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
                              ("LEFTPADDING", (1, 0), (1, 0), 9), ("RIGHTPADDING", (1, 0), (1, 0), 9),
                              ("TOPPADDING", (1, 0), (1, 0), 7), ("BOTTOMPADDING", (1, 0), (1, 0), 8)]))
    return card


def build_pdf(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=20 * mm, bottomMargin=18 * mm,
                            title=f"SecureCheck report: {_plain(result.get('host'), 80)}",
                            author="SecureCheck")
    pages = _Pages(result)
    findings = result.get("findings") or []
    categories = result.get("categories") or []
    story = [Spacer(1, BAND_H - 20 * mm + 8 * mm), _stats(result)]
    strip = _cert_strip(result)
    if strip is not None:
        story += [Spacer(1, 5), strip]

    # Summary by area
    rows = [[Paragraph("Area", CELL_HEAD), Paragraph("To fix", CELL_HEAD),
             Paragraph("To improve", CELL_HEAD), Paragraph("Passed", CELL_HEAD)]]
    for category in categories:
        items = [f for f in findings if f.get("category") == category]
        if not items:
            continue
        n = {s: sum(1 for f in items if f.get("status") == s) for s in ("fail", "warn", "pass")}
        rows.append([Paragraph(_t(category, 60), CELL),
                     Paragraph(_color(RED, str(n["fail"])) if n["fail"] else "0", CELL_NUM),
                     Paragraph(_color(AMBER, str(n["warn"])) if n["warn"] else "0", CELL_NUM),
                     Paragraph(_color(GREEN, str(n["pass"])) if n["pass"] else "0", CELL_NUM)])
    if len(rows) > 1:
        for cell in rows[0][1:]:
            cell.style = ParagraphStyle("ch", parent=CELL_HEAD, alignment=TA_CENTER)
        story += [Paragraph("Summary by area", H2),
                  _grid(rows, [WIDTH - 84 * mm, 28 * mm, 28 * mm, 28 * mm])]

    # Priorities
    urgent = sorted((f for f in findings if f.get("status") == "fail"), key=lambda f: -int(f.get("penalty", 0)))
    if urgent:
        rows = [[Paragraph("", CELL_HEAD), Paragraph("Check that failed", CELL_HEAD),
                 Paragraph("Severity", CELL_HEAD), Paragraph("Area", CELL_HEAD)]]
        for i, f in enumerate(urgent, 1):
            rows.append([Paragraph(str(i), CELL), Paragraph(f"<b>{_t(f.get('title'), 160)}</b>", CELL),
                         Paragraph(_t(f.get("severity"), 10).capitalize(), CELL),
                         Paragraph(_t(f.get("category"), 40), CELL)])
        story += [Paragraph("Fix these first", H2),
                  _grid(rows, [8 * mm, WIDTH - 8 * mm - 24 * mm - 42 * mm, 24 * mm, 42 * mm])]

    # Connection facts
    tls = result.get("tls") or {}
    cert = tls.get("certificate") or {}
    protocols = tls.get("protocols") or {}
    accepted = ", ".join(k for k, v in protocols.items() if v is True) or "none"
    facts = [("Server address", result.get("ip")),
             ("Negotiated", f"{str(tls.get('negotiated', '')).replace('v', ' ')}, {tls.get('cipher', '')}"
              if tls.get("negotiated") else ""),
             ("TLS versions accepted", accepted if protocols else ""),
             ("Certificate issuer", cert.get("issuer")),
             ("Certificate expires", f"{cert.get('expires')} ({cert.get('days_left')} days left)" if cert else ""),
             ("Certificate key", f"{cert.get('key', '')}, {str(cert.get('signature', '')).upper()}" if cert else "")]
    rows = [[Paragraph(_t(k), SMALL), Paragraph(_t(v, 200), CELL)] for k, v in facts if v]
    if rows:
        story.append(KeepTogether([Paragraph("Connection details", H2),
                                   _grid(rows, [46 * mm, WIDTH - 46 * mm], header=False)]))

    # Findings, area by area: problems as cards, passes as a compact list
    for category in categories:
        items = sorted((f for f in findings if f.get("category") == category),
                       key=lambda f: ORDER.get(f.get("status"), 9))
        if not items:
            continue
        problems = [f for f in items if f.get("status") != "pass"]
        passed = [f for f in items if f.get("status") == "pass"]
        heading = Paragraph(_t(category, 60), H2)
        first = True
        for f in problems:
            block = [_card(f), Spacer(1, 6)]
            story.append(KeepTogether([heading] + block if first else block))
            first = False
        if passed:
            rows = [[Paragraph(_color(GREEN, "PASS"), CELL),
                     Paragraph(f"<b>{_t(f.get('title'), 160)}</b><br/>"
                               f"{_color(GREY, _t(f.get('detail'), 300), bold=False)}", CELL)] for f in passed]
            table = _grid(rows, [16 * mm, WIDTH - 16 * mm], header=False)
            story.append(KeepTogether([heading, table]) if first and len(rows) < 12 else table)
            if first and len(rows) >= 12:
                story.insert(len(story) - 1, heading)

    story += _compliance(result)

    story += [Spacer(1, 14), Paragraph(
        "<b>How the score works.</b> Every site starts at 100. A failed check costs its full penalty and a "
        "warning costs half. An untrusted certificate caps the score at 45 and missing HTTPS caps it "
        "at 30. Grades: A+ from 95, A from 85, B from 70, C from 55, D from 40, otherwise F. "
        "This report describes public configuration at the time of the scan.", SMALL)]

    doc.build(story, onFirstPage=pages.first, onLaterPages=pages.later)
    return buf.getvalue()
