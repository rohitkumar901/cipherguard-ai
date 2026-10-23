"""
PDF Security Audit Report Generator for CipherGuard AI.
Compiles password analysis results into a professional forensic document.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from .config import REPORTS_DIR


class SecurityReportGenerator:
    """Generates professional PDF security audit reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            "ReportTitle", parent=self.styles["Heading1"],
            fontSize=22, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0f172a"), spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            "SubTitle", parent=self.styles["Normal"],
            fontSize=11, textColor=colors.HexColor("#475569"), spaceAfter=12,
        ))
        self.styles.add(ParagraphStyle(
            "SectionHead", parent=self.styles["Heading2"],
            fontSize=14, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1e293b"), spaceBefore=14, spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            "Body", parent=self.styles["Normal"],
            fontSize=9.5, textColor=colors.HexColor("#334155"), leading=13,
        ))
        self.styles.add(ParagraphStyle(
            "Danger", parent=self.styles["Normal"],
            fontSize=9.5, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#dc2626"),
        ))
        self.styles.add(ParagraphStyle(
            "Safe", parent=self.styles["Normal"],
            fontSize=9.5, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#16a34a"),
        ))

    def generate(
        self,
        analysis_results: List[Dict],
        filename: Optional[str] = None,
    ) -> Path:
        """Builds the PDF report and returns its path."""
        filename  = filename or f"cipherguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        out_path  = REPORTS_DIR / filename
        doc       = SimpleDocTemplate(str(out_path), pagesize=letter,
                                      leftMargin=36, rightMargin=36,
                                      topMargin=36, bottomMargin=36)
        story     = []
        now_str   = datetime.now().strftime("%B %d, %Y — %H:%M:%S")

        # ── Header ──────────────────────────────────────────────────────────
        story.append(Paragraph("CIPHERGUARD AI // PASSWORD SECURITY AUDIT", self.styles["ReportTitle"]))
        story.append(Paragraph(f"AI-Powered Cryptographic Security Intelligence | Generated: {now_str}", self.styles["SubTitle"]))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=14))

        # ── Executive Summary ────────────────────────────────────────────────
        total    = len(analysis_results)
        safe     = sum(1 for r in analysis_results if r.get("is_safe"))
        critical = sum(1 for r in analysis_results if r.get("score", 0) == 0)
        pwned    = sum(1 for r in analysis_results if r.get("breach_result", {}).get("pwned"))

        summary_data = [
            [Paragraph("<b>Passwords Analyzed</b>", self.styles["Body"]),
             Paragraph("<b>Secure Passwords</b>",   self.styles["Body"]),
             Paragraph("<b>Critical Weak</b>",      self.styles["Body"]),
             Paragraph("<b>Found in Breaches</b>",  self.styles["Body"])],
            [Paragraph(f"<font size=16><b>{total}</b></font>",    self.styles["Body"]),
             Paragraph(f"<font size=16 color='#16a34a'><b>{safe}</b></font>",     self.styles["Body"]),
             Paragraph(f"<font size=16 color='#dc2626'><b>{critical}</b></font>", self.styles["Body"]),
             Paragraph(f"<font size=16 color='#9333ea'><b>{pwned}</b></font>",    self.styles["Body"])],
        ]
        tbl = Table(summary_data, colWidths=[125, 125, 125, 125])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX",        (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID",  (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN",      (0, 1), (-1, 1), "CENTER"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 14))

        # ── Individual Password Analysis Cards ──────────────────────────────
        story.append(Paragraph("DETAILED PASSWORD ANALYSIS DOSSIERS", self.styles["SectionHead"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

        for idx, result in enumerate(analysis_results, 1):
            elements = []
            label    = result.get("strength_label", "UNKNOWN")
            score    = result.get("score", 0)
            pw_disp  = "*" * min(len(result.get("password", "")), 8) + "****"  # Masked
            entropy  = result.get("entropy_bits", 0)
            crack_t  = result.get("crack_time", "?")
            is_safe  = result.get("is_safe", False)

            # Card header
            hdr_data = [[
                Paragraph(f"<b>#{idx} — Password Analysis</b> | Strength: {label} | Score: {score}/4", self.styles["Body"]),
                Paragraph(f"<b>{'✅ SECURE' if is_safe else '❌ VULNERABLE'}</b>",
                          self.styles["Safe"] if is_safe else self.styles["Danger"]),
            ]]
            hdr_tbl = Table(hdr_data, colWidths=[400, 115])
            hdr_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(hdr_tbl)
            elements.append(Spacer(1, 6))

            # Metrics row
            ca = result.get("char_analysis", {})
            metrics_text = (
                f"<b>Entropy:</b> {entropy} bits &nbsp;|&nbsp;"
                f"<b>Crack Time (GPU):</b> {crack_t} &nbsp;|&nbsp;"
                f"<b>Length:</b> {ca.get('length', '?')} chars &nbsp;|&nbsp;"
                f"<b>Uppercase:</b> {ca.get('uppercase', 0)} &nbsp;"
                f"<b>Digits:</b> {ca.get('digits', 0)} &nbsp;"
                f"<b>Symbols:</b> {ca.get('symbols', 0)}"
            )
            elements.append(Paragraph(metrics_text, self.styles["Body"]))
            elements.append(Spacer(1, 4))

            # Patterns
            patterns = result.get("patterns_found", [])
            if patterns:
                pat_text = "<b>⚠️ Patterns Detected:</b> " + " · ".join(patterns)
                elements.append(Paragraph(pat_text, self.styles["Danger"]))
                elements.append(Spacer(1, 4))

            # Suggestions
            sug = result.get("suggestions", [])
            if sug:
                sug_text = "<b>Recommendations:</b><br/>" + "<br/>".join(f"• {s}" for s in sug)
                elements.append(Paragraph(sug_text, self.styles["Body"]))
                elements.append(Spacer(1, 4))

            # Breach result
            breach = result.get("breach_result", {})
            if breach.get("checked"):
                b_color = "#dc2626" if breach.get("pwned") else "#16a34a"
                b_text  = breach.get("message", "")
                elements.append(Paragraph(
                    f"<b>🔍 Breach Check:</b> <font color='{b_color}'>{b_text}</font>",
                    self.styles["Body"]
                ))
                elements.append(Spacer(1, 4))

            elements.append(HRFlowable(width="100%", thickness=0.5,
                                       color=colors.HexColor("#e2e8f0"), spaceAfter=8))
            story.append(KeepTogether(elements))

        # ── Footer ──────────────────────────────────────────────────────────
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            "Generated by <b>CipherGuard AI</b> — AI-Powered Password Security Intelligence Platform | "
            "For educational and security audit purposes only.",
            self.styles["Body"]
        ))

        doc.build(story)
        return out_path
