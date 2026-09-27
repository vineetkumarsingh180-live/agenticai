from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    HRFlowable, Preformatted, Table, TableStyle,
)


def _styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "DocTitle", parent=base["Heading1"],
        fontSize=20, leading=26,
        textColor=colors.HexColor("#1E3A8A"), spaceAfter=10,
    )
    h2 = ParagraphStyle(
        "H2", parent=base["Heading2"],
        fontSize=13, leading=17,
        textColor=colors.HexColor("#1E40AF"),
        spaceBefore=14, spaceAfter=5,
    )
    h3 = ParagraphStyle(
        "H3", parent=base["Heading3"],
        fontSize=11, leading=14,
        textColor=colors.HexColor("#1F2937"),
        spaceBefore=8, spaceAfter=3,
    )
    body = ParagraphStyle(
        "Body", parent=base["Normal"],
        fontSize=9, leading=13,
        textColor=colors.HexColor("#374151"), spaceAfter=4,
    )
    code = ParagraphStyle(
        "Code", parent=base["Code"],
        fontSize=7.5, leading=10,
        backColor=colors.HexColor("#F3F4F6"),
        borderColor=colors.HexColor("#E5E7EB"),
        borderWidth=1, borderPadding=5, spaceAfter=10,
    )
    badge_crit = ParagraphStyle(
        "BadgeCrit", parent=body,
        textColor=colors.white,
        backColor=colors.HexColor("#DC2626"),  # red
        borderPadding=2,
    )
    badge_high = ParagraphStyle(
        "BadgeHigh", parent=body,
        textColor=colors.white,
        backColor=colors.HexColor("#EA580C"),  # orange
        borderPadding=2,
    )
    badge_med = ParagraphStyle(
        "BadgeMed", parent=body,
        textColor=colors.white,
        backColor=colors.HexColor("#CA8A04"),  # amber
        borderPadding=2,
    )
    badge_low = ParagraphStyle(
        "BadgeLow", parent=body,
        textColor=colors.white,
        backColor=colors.HexColor("#16A34A"),  # green
        borderPadding=2,
    )
    return title, h2, h3, body, code, {"CRITICAL": badge_crit, "HIGH": badge_high, "MEDIUM": badge_med, "LOW": badge_low}


def generate_pdf_report(state: dict, output_pdf_path: str):
    """
    Render a professional PDF security audit report from the agent state.

    Args:
        state: The final AgentState dict.
        output_pdf_path: Absolute or relative path for the PDF output.
    """
    title_s, h2_s, h3_s, body_s, code_s, badge_map = _styles()

    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        rightMargin=45, leftMargin=45,
        topMargin=50, bottomMargin=40,
    )

    story = []
    hr_thick = lambda: HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1E3A8A"), spaceAfter=10)
    hr_thin  = lambda: HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#9CA3AF"), spaceAfter=8)

    # ── Title ────────────────────────────────────────────────────────────────
    story.append(Paragraph("Secure Code Audit &amp; Remediation Report", title_s))
    story.append(hr_thick())

    val  = state.get("validation")
    lang = state.get("language", "N/A")
    fp   = state.get("file_path", "N/A")
    syntax_label = "PASSED" if (val and val.is_valid_syntax) else "FAILED"
    syntax_color = "#16A34A" if syntax_label == "PASSED" else "#DC2626"

    meta_data = [
        ["Target File", fp],
        ["Language",    lang],
        ["Syntax Check", syntax_label],
    ]
    meta_table = Table(meta_data, colWidths=[100, 370])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E0E7FF")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.HexColor("#1E40AF")),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ("BOX",        (0, 0), (-1, -1), 0.5, colors.HexColor("#C7D2FE")),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#C7D2FE")),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",  (1, 2), (1, 2), colors.HexColor(syntax_color)),
        ("FONTNAME",   (1, 2), (1, 2), "Helvetica-Bold"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # ── Section 1 : Vulnerability Findings ──────────────────────────────────
    story.append(Paragraph("1. Vulnerability Findings", h2_s))
    story.append(hr_thin())

    analysis = state.get("analysis")
    if not analysis or not analysis.vulnerabilities:
        story.append(Paragraph("✔ No security vulnerabilities detected.", body_s))
    else:
        for idx, v in enumerate(analysis.vulnerabilities, 1):
            sev = v.severity.upper()
            badge_s = badge_map.get(sev, badge_map["LOW"])

            story.append(Paragraph(
                f"Finding {idx}: {v.title} <font color='#6B7280'>({v.cwe_id})</font>",
                h3_s
            ))
            story.append(Paragraph(f"Severity: <b>{sev}</b>", badge_s))
            story.append(Spacer(1, 4))

            details = [
                ["Vulnerable Line(s)", str(v.vulnerable_lines)],
                ["Risk &amp; Impact",  v.risk_impact],
                ["Technical Breakdown", v.explanation],
            ]
            dtable = Table(details, colWidths=[130, 340])
            dtable.setStyle(TableStyle([
                ("FONTNAME",       (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE",       (0, 0), (-1, -1), 9),
                ("BACKGROUND",     (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
                ("TEXTCOLOR",      (0, 0), (0, -1), colors.HexColor("#4B5563")),
                ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN",         (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",     (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
                ("LEFTPADDING",    (0, 0), (-1, -1), 8),
                ("BOX",            (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
                ("GRID",           (0, 0), (-1, -1), 0.25, colors.HexColor("#E5E7EB")),
                ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ]))
            story.append(dtable)
            story.append(Spacer(1, 10))

    # ── Section 2 : Remediations ─────────────────────────────────────────────
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Remediations &amp; Patches Applied", h2_s))
    story.append(hr_thin())

    patch = state.get("patch")
    if patch and patch.changes_made:
        story.append(Paragraph("<b>Key Changes Made:</b>", h3_s))
        for ch in patch.changes_made:
            story.append(Paragraph(f"• {ch}", body_s))
        story.append(Spacer(1, 8))

    if patch and patch.patched_code:
        story.append(Paragraph("<b>Patched Source Code:</b>", h3_s))
        story.append(Preformatted(patch.patched_code, code_s))

    doc.build(story)
