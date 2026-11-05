"""PDF Report Generator for Cipher-Lens using ReportLab (Task A9).

Renders complete assessment reports with:
- Cover page and Table of Contents
- Section 1: Executive Summary & Assessment Scope
- Section 2: Assessment Methodology & Rules of Engagement
- Section 3: Severity Distribution Chart & Prioritized Findings
- Section 4: Detailed Vulnerability Findings (with evidence/inference separation)
- Section 5: Business Impact & Actionable Remediation
- Section 6: Assessment Limitations & Transparency Disclosures
- Appendices: Evidence Index, Tool Execution, Approvals & Audit Integrity
- Two-pass NumberedCanvas with headers and footers
"""

import io
import xml.sax.saxutils
from pathlib import Path
from typing import Any

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from cipher_lens.reports.canvas import NumberedCanvas
from cipher_lens.reports.models import ReportData


def safe_para(text: Any, style: Any) -> Paragraph:
    """Escapes XML entities before instantiating ReportLab Paragraph (ERR-23)."""
    clean = xml.sax.saxutils.escape(str(text or ""))
    return Paragraph(clean, style)


def _get_styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=sample["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        alignment=0,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569"),
    )

    h1_style = ParagraphStyle(
        "ReportH1",
        parent=sample["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "ReportH2",
        parent=sample["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=sample["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B"),
    )

    callout_style = ParagraphStyle(
        "ReportCallout",
        parent=sample["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569"),
    )

    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "h1": h1_style,
        "h2": h2_style,
        "body": body_style,
        "code": code_style,
        "callout": callout_style,
    }


def _make_severity_chart(data: ReportData) -> Drawing:
    """Builds a horizontal colored bar chart of finding severities."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in data.findings:
        sev = (f.tool_severity or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1

    total = sum(counts.values()) or 1

    d = Drawing(480, 80)
    palette = {
        "critical": colors.HexColor("#DC2626"),
        "high": colors.HexColor("#EA580C"),
        "medium": colors.HexColor("#D97706"),
        "low": colors.HexColor("#2563EB"),
        "info": colors.HexColor("#64748B"),
    }

    y = 55
    bar_height = 14
    max_bar_width = 320

    # Background frame
    d.add(Rect(0, 0, 480, 80, fillColor=colors.HexColor("#F8FAFC"), strokeColor=colors.HexColor("#E2E8F0"), strokeWidth=1))

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts[sev]
        bar_w = max(4, int((count / total) * max_bar_width)) if count > 0 else 0
        d.add(String(10, y + 2, f"{sev.capitalize()}: {count}", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#1E293B")))
        if bar_w > 0:
            d.add(Rect(90, y, bar_w, bar_height, fillColor=palette[sev], strokeColor=None))
        y -= 12

    return d


def build_report_flowables(data: ReportData) -> list[Any]:
    """Assembles all ReportLab flowable elements for the PDF."""
    styles = _get_styles()
    flowables: list[Any] = []

    # -----------------------------------------------------------------------
    # Cover Page
    # -----------------------------------------------------------------------
    flowables.append(Spacer(1, 40))
    flowables.append(Paragraph("PENETRATION TESTING &amp; VULNERABILITY ASSESSMENT REPORT", styles["title"]))
    flowables.append(Spacer(1, 8))
    flowables.append(Paragraph("Cipher-Lens Autonomous VAPT Assistant — Comprehensive Assessment", styles["subtitle"]))
    flowables.append(Spacer(1, 35))

    cover_meta = [
        [Paragraph("<b>Target Asset:</b>", styles["body"]), Paragraph(data.scope_target, styles["body"])],
        [Paragraph("<b>Assessment ID:</b>", styles["body"]), Paragraph(data.assessment.id, styles["body"])],
        [Paragraph("<b>Status:</b>", styles["body"]), Paragraph(data.assessment.status.value.upper(), styles["body"])],
        [Paragraph("<b>Authorization Ref:</b>", styles["body"]), Paragraph(data.scope_reference, styles["body"])],
        [Paragraph("<b>Generated Date:</b>", styles["body"]), Paragraph(data.assessment.created_at.strftime("%Y-%m-%d %H:%M UTC"), styles["body"])],
        [Paragraph("<b>Assessor:</b>", styles["body"]), Paragraph("Cipher-Lens Autonomous Assessor", styles["body"])],
    ]
    meta_table = Table(cover_meta, colWidths=[130, 350])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    flowables.append(meta_table)

    flowables.append(Spacer(1, 140))
    flowables.append(
        Paragraph(
            "<b>STRICTLY CONFIDENTIAL</b> — This report contains proprietary security assessment findings "
            "conducted under authorized engagement rules. Unauthorized reproduction or dissemination is prohibited.",
            styles["callout"],
        )
    )
    flowables.append(PageBreak())

    # -----------------------------------------------------------------------
    # Table of Contents
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("Table of Contents", styles["h1"]))
    flowables.append(Spacer(1, 10))

    toc_entries = [
        ["1.", "Executive Summary & Assessment Scope", "Page 3"],
        ["2.", "Assessment Methodology & Rules of Engagement", "Page 3"],
        ["3.", "Severity Distribution & Prioritized Findings", "Page 4"],
        ["4.", "Detailed Vulnerability Findings", "Page 5"],
        ["5.", "Business Impact & Actionable Remediation", "Page 6"],
        ["6.", "Assessment Limitations & Transparency Disclosures", "Page 7"],
        ["A.", "Appendix A: Evidence & Artifact Verification Index", "Page 8"],
        ["B.", "Appendix B: Tool Execution & Integration Summary", "Page 8"],
        ["C.", "Appendix C: Human-in-the-Loop Approvals & Audit Trail", "Page 9"],
    ]
    toc_data = [[Paragraph(f"<b>{num}</b>", styles["body"]), Paragraph(title, styles["body"]), Paragraph(page, styles["body"])] for num, title, page in toc_entries]
    toc_table = Table(toc_data, colWidths=[30, 400, 70])
    toc_table.setStyle(
        TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )
    flowables.append(toc_table)
    flowables.append(PageBreak())

    # -----------------------------------------------------------------------
    # 1. Executive Summary & Assessment Scope
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("1. Executive Summary &amp; Assessment Scope", styles["h1"]))
    flowables.append(
        Paragraph(
            f"Cipher-Lens conducted an authorized security assessment against target <b>{data.scope_target}</b> "
            f"under authorization reference <b>{data.scope_reference}</b>. The evaluation employed automated port scanning, "
            f"web service discovery, vulnerability enrichment (NVD, CISA KEV, FIRST EPSS), and policy-governed active probes. "
            f"All activities complied strictly with the registered rules of engagement and safety boundaries.",
            styles["body"],
        )
    )
    flowables.append(Spacer(1, 8))

    if data.executive_summary:
        flowables.append(Paragraph("Executive Assessment Narrative", styles["h2"]))
        for p_chunk in data.executive_summary.split("\n\n"):
            p_clean = p_chunk.strip()
            if p_clean:
                flowables.append(Paragraph(p_clean, styles["body"]))
                flowables.append(Spacer(1, 4))
        flowables.append(Spacer(1, 6))

    crit_count = sum(1 for f in data.findings if (f.tool_severity or "").lower() == "critical")
    high_count = sum(1 for f in data.findings if (f.tool_severity or "").lower() == "high")
    med_count = sum(1 for f in data.findings if (f.tool_severity or "").lower() == "medium")

    exec_summary_rows = [
        [Paragraph("<b>Target Host/IP</b>", styles["body"]), Paragraph(data.scope_target, styles["body"])],
        [Paragraph("<b>Authorized Window</b>", styles["body"]), Paragraph(data.testing_window, styles["body"])],
        [Paragraph("<b>Total Findings</b>", styles["body"]), Paragraph(str(len(data.findings)), styles["body"])],
        [Paragraph("<b>High / Critical Issues</b>", styles["body"]), Paragraph(f"{high_count} High, {crit_count} Critical, {med_count} Medium", styles["body"])],
        [Paragraph("<b>Summary Provenance</b>", styles["body"]), Paragraph(data.executive_summary_badge, styles["body"])],
        [Paragraph("<b>Audit Status</b>", styles["body"]), Paragraph("Verified Cryptographic Hash Chain" if data.audit_verified else "Audit Verification Pending", styles["body"])],
    ]
    exec_table = Table(exec_summary_rows, colWidths=[140, 340])
    exec_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    flowables.append(exec_table)
    flowables.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 2. Assessment Methodology & Rules of Engagement
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("2. Assessment Methodology &amp; Rules of Engagement", styles["h1"]))
    flowables.append(
        Paragraph(
            "The assessment followed the <b>NIST SP 800-115 Technical Guide to Information Security Testing</b> methodology across four core phases: "
            "(1) Planning &amp; Scope Enforcement, (2) Discovery &amp; Service Identification, (3) Vulnerability Correlation &amp; Controlled Probing, "
            "and (4) Reporting &amp; Remediation Analysis. Tool execution went through mandatory pre-execution scope checks (PolicyGate) "
            "and per-step human approval gates (ApprovalManager) before intrusive scanners were spawned.",
            styles["body"],
        )
    )
    flowables.append(Spacer(1, 8))

    flowables.append(Paragraph("Tool Execution Summary", styles["h2"]))
    tool_rows = [
        [
            Paragraph("<b>Tool</b>", styles["body"]),
            Paragraph("<b>Status</b>", styles["body"]),
            Paragraph("<b>Duration</b>", styles["body"]),
            Paragraph("<b>Artifact SHA-256</b>", styles["body"]),
        ]
    ]
    for r in data.runs:
        sha_display = (r.raw_sha256[:16] + "...") if r.raw_sha256 else "None"
        dur_str = f"{r.duration_ms / 1000:.1f}s" if r.duration_ms is not None else "-"
        status_style = styles["body"]
        tool_rows.append([
            Paragraph(r.tool_name, styles["body"]),
            Paragraph(r.status.upper(), status_style),
            Paragraph(dur_str, styles["body"]),
            Paragraph(sha_display, styles["code"]),
        ])

    tool_table = Table(tool_rows, colWidths=[90, 80, 80, 230])
    tool_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(tool_table)
    flowables.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 3. Severity Distribution & Prioritized Findings
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("3. Severity Distribution &amp; Prioritized Findings", styles["h1"]))
    flowables.append(_make_severity_chart(data))
    flowables.append(Spacer(1, 10))

    flowables.append(Paragraph("Prioritized Findings Table", styles["h2"]))
    find_summary_rows = [
        [
            Paragraph("<b>ID</b>", styles["body"]),
            Paragraph("<b>Finding Title</b>", styles["body"]),
            Paragraph("<b>Severity</b>", styles["body"]),
            Paragraph("<b>Confidence</b>", styles["body"]),
            Paragraph("<b>Composite Risk</b>", styles["body"]),
        ]
    ]
    if data.findings:
        for f in data.findings:
            risk_str = f"{f.risk.total:.1f} ({f.risk.band})" if f.risk else "N/A"
            find_summary_rows.append([
                Paragraph(f.id, styles["code"]),
                Paragraph(f.title[:45], styles["body"]),
                Paragraph(f.tool_severity.upper(), styles["body"]),
                Paragraph(f.confidence.capitalize(), styles["body"]),
                Paragraph(risk_str, styles["body"]),
            ])
    else:
        find_summary_rows.append([
            Paragraph("-", styles["body"]),
            Paragraph("No vulnerabilities discovered within scope.", styles["body"]),
            Paragraph("-", styles["body"]),
            Paragraph("-", styles["body"]),
            Paragraph("-", styles["body"]),
        ])

    find_summary_table = Table(find_summary_rows, colWidths=[65, 205, 70, 70, 70])
    find_summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(find_summary_table)
    flowables.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 4. Detailed Vulnerability Findings
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("4. Detailed Vulnerability Findings", styles["h1"]))
    if not data.findings:
        flowables.append(Paragraph("No vulnerabilities identified within authorized scope.", styles["body"]))
    else:
        for finding in data.findings:
            flowables.append(
                Paragraph(f"<b>[{finding.id}] {finding.title} — {finding.tool_severity.upper()}</b>", styles["h2"])
            )

            cvss_str = (
                f"{finding.cvss.score} (v{finding.cvss.version}, source: {finding.cvss.source})"
                if finding.cvss
                else "Unassigned / Not reported"
            )
            cve_str = ", ".join(finding.cve) if finding.cve else "None reported"
            cwe_str = ", ".join(finding.cwe) if finding.cwe else "None reported"

            f_meta = [
                [Paragraph("<b>Asset:</b>", styles["body"]), safe_para(f"{finding.asset.host}:{finding.asset.port or ''}{finding.asset.url_path or ''}", styles["body"])],
                [Paragraph("<b>Status:</b>", styles["body"]), safe_para(f"{finding.status.upper()} ({finding.status_reason})", styles["body"])],
                [Paragraph("<b>CVE / CWE:</b>", styles["body"]), safe_para(f"CVE: {cve_str} | CWE: {cwe_str}", styles["body"])],
                [Paragraph("<b>CVSS:</b>", styles["body"]), safe_para(cvss_str, styles["body"])],
            ]
            f_table = Table(f_meta, colWidths=[90, 390])
            f_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ])
            )
            flowables.append(f_table)
            flowables.append(Spacer(1, 6))

            # Observed Direct Evidence (strictly demarcated per AGENTS.md Rule 4)
            flowables.append(Paragraph("<b>Observed Technical Evidence:</b>", styles["body"]))
            for ev in finding.evidence:
                ev_box = [
                    [Paragraph(f"<b>Tool:</b> {xml.sax.saxutils.escape(ev.source_tool)} | <b>Locator:</b> {xml.sax.saxutils.escape(ev.locator)} | <b>SHA-256:</b> {ev.raw_sha256[:16]}...", styles["code"])],
                    [safe_para(ev.snippet, styles["code"])],
                ]
                ev_table = Table(ev_box, colWidths=[480])
                ev_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                flowables.append(ev_table)
                flowables.append(Spacer(1, 4))

            # AI Inferences (strictly labeled and separated per AGENTS.md Rule 4)
            if finding.inferences:
                flowables.append(Paragraph("<b>AI Analytical Inference (Non-Evidence):</b>", styles["body"]))
                for inf in finding.inferences:
                    inf_box = [
                        [Paragraph(f"<b>Provider:</b> {xml.sax.saxutils.escape(inf.provider)} | <b>Label:</b> {xml.sax.saxutils.escape(inf.label)}", styles["callout"])],
                        [safe_para(inf.text, styles["callout"])],
                    ]
                    inf_table = Table(inf_box, colWidths=[480])
                    inf_table.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#3B82F6")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ])
                    )
                    flowables.append(inf_table)
                    flowables.append(Spacer(1, 4))

            flowables.append(Spacer(1, 8))

    flowables.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # 5. Business Impact & Actionable Remediation
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("5. Business Impact &amp; Actionable Remediation", styles["h1"]))
    flowables.append(
        Paragraph(
            "Identified vulnerabilities may introduce exposure to unauthorized access, remote code execution, or "
            "sensitive data disclosure. The following remediation matrix outlines prioritized mitigations mapped to industry standards:",
            styles["body"],
        )
    )
    flowables.append(Spacer(1, 6))

    remediation_rows = [
        [
            Paragraph("<b>Priority</b>", styles["body"]),
            Paragraph("<b>Target Asset</b>", styles["body"]),
            Paragraph("<b>Remediation Action</b>", styles["body"]),
            Paragraph("<b>NIST CSF 2.0</b>", styles["body"]),
        ]
    ]
    if data.findings:
        for f in data.findings:
            remediation_rows.append([
                Paragraph(f.tool_severity.upper(), styles["body"]),
                Paragraph(f"{f.asset.host}:{f.asset.port or ''}", styles["body"]),
                Paragraph(f"Upgrade software packages and review configuration for {f.title[:30]}", styles["body"]),
                Paragraph("PROTECT (PR.PS-01)", styles["body"]),
            ])
    else:
        remediation_rows.append([
            Paragraph("INFO", styles["body"]),
            Paragraph(data.scope_target, styles["body"]),
            Paragraph("Maintain baseline patching schedule and continuous monitoring.", styles["body"]),
            Paragraph("IDENTIFY (ID.RA-01)", styles["body"]),
        ])

    rem_table = Table(remediation_rows, colWidths=[70, 110, 200, 100])
    rem_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(rem_table)
    flowables.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 6. Assessment Limitations & Transparency Disclosures
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("6. Assessment Limitations &amp; Transparency Disclosures", styles["h1"]))
    flowables.append(
        Paragraph(
            "<b>Engagement Boundaries &amp; Execution Limitations:</b>",
            styles["body"],
        )
    )
    for lim in data.limitations:
        flowables.append(Paragraph(f"• {lim}", styles["body"]))

    flowables.append(Spacer(1, 6))
    flowables.append(
        Paragraph(
            "<b>Standards &amp; Heuristic Scoring Disclaimers:</b><br/>"
            "• References to NIST SP 800-115, NIST CSF 2.0, OWASP Top 10, and CWE do not establish formal regulatory or compliance certification.<br/>"
            "• Composite risk scores are heuristic calculations based on observed factors (CVSS, CISA KEV, EPSS) and do not replace custom risk evaluations.<br/>"
            "• Observed technical evidence and AI inferences are strictly segregated; inferences do not constitute factual evidence.",
            styles["callout"],
        )
    )
    flowables.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # Appendices
    # -----------------------------------------------------------------------
    flowables.append(Paragraph("Appendix A: Evidence &amp; Artifact Verification Index", styles["h1"]))
    ev_index_rows = [
        [
            Paragraph("<b>Evidence ID</b>", styles["body"]),
            Paragraph("<b>Tool</b>", styles["body"]),
            Paragraph("<b>Artifact ID</b>", styles["body"]),
            Paragraph("<b>Raw SHA-256</b>", styles["body"]),
            Paragraph("<b>Locator</b>", styles["body"]),
        ]
    ]
    for ev in data.evidence:
        ev_index_rows.append([
            Paragraph(ev.id, styles["code"]),
            Paragraph(ev.source_tool, styles["body"]),
            Paragraph(ev.artifact_id, styles["body"]),
            Paragraph(ev.raw_sha256[:16] + "...", styles["code"]),
            Paragraph(ev.locator, styles["code"]),
        ])
    if not data.evidence:
        ev_index_rows.append([Paragraph("-", styles["body"]), Paragraph("No artifacts recorded.", styles["body"]), Paragraph("-", styles["body"]), Paragraph("-", styles["body"]), Paragraph("-", styles["body"])])

    ev_table = Table(ev_index_rows, colWidths=[70, 60, 100, 120, 130])
    ev_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(ev_table)
    flowables.append(Spacer(1, 12))

    flowables.append(Paragraph("Appendix B: Tool Execution &amp; Integration Summary", styles["h1"]))
    flowables.append(
        Paragraph(
            "Cipher-Lens integrates with Nmap, Nikto, and OWASP ZAP for live active scanning, "
            "and supports offline artifact imports for Nessus, OpenVAS, and Burp Suite XML reports.",
            styles["body"],
        )
    )
    flowables.append(Spacer(1, 12))

    flowables.append(Paragraph("Appendix C: Human-in-the-Loop Approvals &amp; Audit Trail", styles["h1"]))
    audit_summary_rows = [
        [Paragraph("<b>Audit Events Count:</b>", styles["body"]), Paragraph(str(data.audit_event_count), styles["body"])],
        [Paragraph("<b>Chain Head Hash:</b>", styles["body"]), Paragraph(data.audit_head_hash[:32] + "...", styles["code"])],
        [Paragraph("<b>Integrity Verification:</b>", styles["body"]), Paragraph("PASS (Chain Verified Untampered)" if data.audit_verified else "FAIL", styles["body"])],
    ]
    audit_table = Table(audit_summary_rows, colWidths=[160, 320])
    audit_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(audit_table)

    return flowables


class PdfReportGenerator:
    """Renders assessment reports to PDF files or bytes."""

    def __init__(self) -> None:
        pass

    def generate_to_bytes(self, data: ReportData) -> bytes:
        """Renders report data into in-memory PDF bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )
        flowables = build_report_flowables(data)
        doc.build(flowables, canvasmaker=NumberedCanvas)
        return buffer.getvalue()

    def generate_to_file(self, data: ReportData, output_path: Path | str) -> Path:
        """Renders report data directly to a destination PDF file."""
        target_path = Path(output_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(target_path),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )
        flowables = build_report_flowables(data)
        doc.build(flowables, canvasmaker=NumberedCanvas)
        return target_path
