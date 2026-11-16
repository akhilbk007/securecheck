"""Builds the downloadable PDF report from a scan result.

Everything in a scan result that came from the scanned site (header values,
cookie names, certificate fields) is untrusted. ReportLab paragraphs accept a
small markup language, so every value is escaped before it is placed.
"""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

INK = colors.HexColor("#0f2438")
SOFT = colors.HexColor("#4b5f72")
RULE = colors.HexColor("#c4d0da")
PANEL = colors.HexColor("#eef2f6")
STATUS = {
    "fail": ("Fail", colors.HexColor("#b3232b")),
    "warn": ("Warn", colors.HexColor("#9a5b00")),
    "pass": ("Pass", colors.HexColor("#146c43")),
    "info": ("Note", SOFT),
}
GRADE_COLOR = {"A+": "#146c43", "A": "#146c43", "B": "#146c43", "C": "#9a5b00", "D": "#9a5b00", "F": "#b3232b"}
ORDER = {"fail": 0, "warn": 1, "info": 2, "pass": 3}

BODY = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8.5, leading=12, textColor=SOFT)
RIGHT = ParagraphStyle("right", parent=SMALL, alignment=TA_RIGHT)
H1 = ParagraphStyle("h1", parent=BODY, fontName="Helvetica-Bold", fontSize=22, leading=26)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=14, spaceAfter=6)
TITLE = ParagraphStyle("title", parent=BODY, fontName="Helvetica-Bold", fontSize=10.5, leading=14)
CODE = ParagraphStyle("code", parent=BODY, fontName="Courier", fontSize=8, leading=11, textColor=INK,
                      backColor=PANEL, borderPadding=(4, 5, 4, 5), spaceBefore=4, spaceAfter=6)
FIX = ParagraphStyle("fix", parent=BODY, leftIndent=8, borderPadding=(0, 0, 0, 6))


def _t(value, limit: int = 900) -> str:
    """Make any value safe to place in a paragraph."""
    text = str(value if value is not None else "")[:limit]
    text = text.encode("latin-1", "replace").decode("latin-1")  # built-in PDF fonts are Latin-1
    text = "".join(ch if ch >= " " or ch == "\n" else " " for ch in text)
    return escape(text)


def _break_long(text: str, every: int = 80) -> str:
    """Let long unbroken values (policies, hashes) wrap inside the page."""
    out = []
    for word in text.split(" "):
        while len(word) > every:
            out.append(word[:every])
            word = word[every:]
        out.append(word)
    return " ".join(out)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SOFT)
    canvas.drawString(18 * mm, 10 * mm, "SecureCheck report. Passive configuration check, not a penetration test.")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm,
                            title=f"SecureCheck report: {result.get('host', '')}"[:120],
                            author="SecureCheck")
    width = A4[0] - 36 * mm
    story = []

    grade = str(result.get("grade", "?"))
    grade_hex = GRADE_COLOR.get(grade, "#0f2438")
    counts = result.get("counts", {})
    head = Table(
        [[
            [Paragraph("Website security report", SMALL),
             Paragraph(_t(result.get("host"), 80), H1),
             Spacer(1, 4),
             Paragraph(f"Scanned {_t(result.get('scanned_at'))} (UTC)", SMALL),
             Paragraph(f"{_t(result.get('final_url'), 160)}", SMALL)],
            [Paragraph(f'<font size="40" color="{grade_hex}"><b>{_t(grade, 2)}</b></font>',
                       ParagraphStyle("g", parent=BODY, alignment=TA_RIGHT, leading=42)),
             Paragraph(f"{int(result.get('score', 0))} / 100", RIGHT)],
        ]],
        colWidths=[width - 40 * mm, 40 * mm],
    )
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                              ("LINEBELOW", (0, 0), (-1, 0), 1, INK), ("BOTTOMPADDING", (0, 0), (-1, 0), 10)]))
    story += [head, Spacer(1, 8)]
    story.append(Paragraph(
        f'<font color="#b3232b"><b>{int(counts.get("fail", 0))} to fix</b></font> &nbsp;&nbsp; '
        f'<font color="#9a5b00"><b>{int(counts.get("warn", 0))} to improve</b></font> &nbsp;&nbsp; '
        f'<font color="#146c43"><b>{int(counts.get("pass", 0))} passed</b></font>', BODY))

    # Connection facts
    tls = result.get("tls") or {}
    cert = tls.get("certificate") or {}
    protocols = tls.get("protocols") or {}
    accepted = ", ".join(k for k, v in protocols.items() if v is True) or "none"
    facts = [("Server address", result.get("ip")),
             ("Negotiated", f"{str(tls.get('negotiated', '')).replace('v', ' ')}  {tls.get('cipher', '')}".strip()),
             ("Versions accepted", accepted if protocols else ""),
             ("Certificate issuer", cert.get("issuer")),
             ("Certificate expires", f"{cert.get('expires')} ({cert.get('days_left')} days)" if cert else ""),
             ("Certificate key", f"{cert.get('key', '')}, {str(cert.get('signature', '')).upper()}" if cert else "")]
    rows = [[Paragraph(_t(k), SMALL), Paragraph(_t(v, 200), BODY)] for k, v in facts if v]
    if rows:
        table = Table(rows, colWidths=[42 * mm, width - 42 * mm])
        table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LINEBELOW", (0, 0), (-1, -1), 0.5, RULE),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                   ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        story += [Paragraph("Connection", H2), table]

    # Priority list
    findings = result.get("findings") or []
    urgent = [f for f in findings if f.get("status") == "fail"]
    if urgent:
        story.append(Paragraph("Fix these first", H2))
        for f in sorted(urgent, key=lambda f: -int(f.get("penalty", 0))):
            story.append(Paragraph(f"&bull; <b>{_t(f.get('title'), 160)}</b> ({_t(f.get('severity'), 10)} severity)", BODY))

    # Full findings by category
    for category in result.get("categories") or []:
        items = sorted((f for f in findings if f.get("category") == category),
                       key=lambda f: ORDER.get(f.get("status"), 9))
        if not items:
            continue
        story.append(Paragraph(_t(category, 60), H2))
        for f in items:
            label, color = STATUS.get(f.get("status"), ("Note", SOFT))
            block = [Paragraph(f'<font color="{color.hexval().replace("0x", "#")}"><b>{label}</b></font>'
                               f" &nbsp; {_t(f.get('title'), 160)}", TITLE),
                     Paragraph(_t(f.get("detail")), BODY)]
            if f.get("evidence"):
                block.append(Paragraph(_t(_break_long(str(f["evidence"])), 600), CODE))
            if f.get("fix") and f.get("status") in ("fail", "warn"):
                block.append(Paragraph(f"<b>Fix:</b> {_t(_break_long(str(f['fix'])))}", FIX))
            ref = str(f.get("reference") or "")
            if ref.startswith("https://"):
                block.append(Paragraph(f"More: {_t(ref, 200)}", SMALL))
            block.append(Spacer(1, 9))
            story.append(KeepTogether(block))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "How the score works: every site starts at 100. A failed check costs its full penalty and a "
        "warning costs half. An untrusted certificate caps the score at 45 and missing HTTPS caps it "
        "at 30. Grades: A+ from 95, A from 85, B from 70, C from 55, D from 40, otherwise F. "
        "This report describes public configuration at the time of the scan.", SMALL))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
