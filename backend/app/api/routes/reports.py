
import html
import io
import json
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.report_generator import generate_forensic_report

router = APIRouter(prefix="/reports", tags=["Forensic Reports"])


def _text(value, default="Not recorded"):
    """Convert arbitrary report values into safe, printable text."""
    if value is None or value == "":
        value = default

    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)

    return str(value)


def _paragraph(value, style):
    """Escape untrusted database content before rendering as PDF markup."""
    value = _text(value)
    return Paragraph(
        escape(value).replace("\n", "<br/>"),
        style,
    )


def _timestamp(value):
    if not value:
        return "Not recorded"

    value = str(value)

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S %z").strip()
    except (ValueError, TypeError):
        return value


async def _create_report(db, case_id: str, evidence_id: str | None):
    try:
        return await generate_forensic_report(db, case_id, evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to generate report: {exc}",
        ) from exc


def _page_footer(canvas, doc):
    """Add a consistent footer and page number to every page."""
    canvas.saveState()
    page_width, _ = doc.pagesize

    canvas.setStrokeColorRGB(0.82, 0.85, 0.89)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 30, page_width - doc.rightMargin, 30)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColorRGB(0.35, 0.39, 0.45)
    canvas.drawString(doc.leftMargin, 18, "NetForensicX | Forensic Investigation")
    canvas.drawRightString(
        page_width - doc.rightMargin,
        18,
        f"Page {doc.page}",
    )
    canvas.restoreState()


def _section(title, styles, story):
    story.append(Paragraph(escape(title), styles["SectionHeading"]))
    story.append(Spacer(1, 5))


def _make_table(rows, widths, colors, styles, repeat_rows=1):
    """Create a styled, paginating table with wrapped cell content."""
    table = Table(
        rows,
        colWidths=widths,
        repeatRows=repeat_rows,
        hAlign="LEFT",
        splitByRow=1,
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D5DAE2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F5F7FA"),
        ]),
    ]))

    return table


@router.get("/cases/{case_id}")
async def get_case_report(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    return await _create_report(db, case_id, evidence_id)


@router.get("/cases/{case_id}/export.json")
async def export_case_report_json(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    report = await _create_report(db, case_id, evidence_id)

    filename = f"netforensicx-report-{case_id}.json"
    content = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/cases/{case_id}/export.pdf")
async def export_case_report_pdf(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    report = await _create_report(db, case_id, evidence_id)

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import (
            getSampleStyleSheet,
            ParagraphStyle,
        )
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
            KeepTogether,
        )
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail=(
                "PDF export requires reportlab. Add reportlab to "
                "backend dependencies and rebuild the API image."
            ),
        ) from exc

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=19 * mm,
        bottomMargin=17 * mm,
        title="NetForensicX Forensic Investigation Report",
        author="NetForensicX",
        subject=f"Forensic report for case {case_id}",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=29,
        textColor=colors.HexColor("#172033"),
        alignment=TA_CENTER,
        spaceAfter=12,
    ))

    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=16,
        textColor=colors.HexColor("#526078"),
        alignment=TA_CENTER,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#172033"),
        spaceBefore=13,
        spaceAfter=7,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="SubsectionHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#263650"),
        spaceBefore=7,
        spaceAfter=4,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        spaceAfter=5,
        splitLongWords=1,
        wordWrap="LTR",
    ))

    styles.add(ParagraphStyle(
        name="SmallReportText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        splitLongWords=1,
        wordWrap="LTR",
    ))

    styles.add(ParagraphStyle(
        name="TableCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        splitLongWords=1,
        wordWrap="LTR",
    ))

    styles.add(ParagraphStyle(
        name="CoverMetadata",
        parent=styles["BodyText"],
        fontSize=9,
        leading=15,
        alignment=TA_CENTER,
    ))

    story = []

    case = report.get("case") or {}
    evidence_items = report.get("evidence") or []
    summary = report.get("summary") or {}
    detections = report.get("detections") or []
    iocs = report.get("iocs") or []
    timeline = report.get("timeline") or []
    mitre = report.get("mitre_mappings") or []
    limitations = report.get("limitations") or []

    case_title = case.get("title") or case.get("id") or case_id

    # ---------------------------------------------------------
    # 1. Cover and case information
    # ---------------------------------------------------------
    story.extend([
        Spacer(1, 28 * mm),
        Paragraph("NetForensicX", styles["CoverTitle"]),
        Paragraph(
            "FORENSIC INVESTIGATION REPORT",
            styles["CoverSubtitle"],
        ),
        Spacer(1, 12 * mm),
        Paragraph(
            escape(_text(case_title)),
            ParagraphStyle(
                "CaseCoverTitle",
                parent=styles["Heading1"],
                alignment=TA_CENTER,
                textColor=colors.HexColor("#172033"),
                fontSize=17,
                leading=22,
            ),
        ),
        Spacer(1, 8 * mm),
        Paragraph(
            f"<b>Case ID:</b> {escape(_text(case_id))}<br/>"
            f"<b>Report generated:</b> "
            f"{escape(_timestamp(report.get('generated_at')))}<br/>"
            f"<b>Case status:</b> "
            f"{escape(_text(case.get('status')))}<br/>"
            f"<b>Evidence records:</b> {len(evidence_items)}",
            styles["CoverMetadata"],
        ),
        Spacer(1, 12 * mm),
    ])

    if case.get("description"):
        story.append(Paragraph("Case Description", styles["SubsectionHeading"]))
        story.append(_paragraph(case["description"], styles["ReportBody"]))

    story.append(Paragraph(
        "Scope: this document summarizes analysis records available to "
        "NetForensicX at the time of report generation. It is not, by itself, "
        "proof that a host was compromised or that a recovered file executed.",
        styles["ReportBody"],
    ))

    story.append(PageBreak())

    # ---------------------------------------------------------
    # 2. Executive summary
    # ---------------------------------------------------------
    _section("1. Executive Summary", styles, story)

    summary_rows = [
        [
            _paragraph("Metric", styles["TableCell"]),
            _paragraph("Recorded value", styles["TableCell"]),
        ]
    ]

    metric_labels = [
        ("evidence_count", "Evidence records"),
        ("flow_count", "Network flows"),
        ("detection_count", "Detections"),
        ("ioc_count", "Indicators of compromise (IOCs)"),
        ("timeline_event_count", "Timeline events"),
        ("mitre_mapping_count", "MITRE ATT&CK mappings"),
    ]

    for key, label in metric_labels:
        summary_rows.append([
            _paragraph(label, styles["TableCell"]),
            _paragraph(summary.get(key, 0), styles["TableCell"]),
        ])

    summary_table = _make_table(
        summary_rows,
        [105 * mm, 65 * mm],
        colors,
        styles,
    )
    story.append(summary_table)
    story.append(Spacer(1, 7))

    _section("Detection Severity Breakdown", styles, story)

    severity_counts = summary.get("detections_by_severity") or {}
    if severity_counts:
        severity_rows = [[
            _paragraph("Severity", styles["TableCell"]),
            _paragraph("Count", styles["TableCell"]),
        ]]

        for severity, count in sorted(severity_counts.items()):
            severity_rows.append([
                _paragraph(severity.title(), styles["TableCell"]),
                _paragraph(count, styles["TableCell"]),
            ])

        story.append(_make_table(
            severity_rows,
            [105 * mm, 65 * mm],
            colors,
            styles,
        ))
    else:
        story.append(Paragraph(
            "No severity breakdown was recorded.",
            styles["ReportBody"],
        ))

    story.append(Paragraph(
        f"The database contains {len(detections)} detection record(s), "
        f"{len(iocs)} IOC record(s), {len(timeline)} timeline event(s), "
        f"and {len(mitre)} MITRE ATT&CK mapping(s) for the selected scope. "
        "These counts describe stored records, not independently verified "
        "malicious activity.",
        styles["ReportBody"],
    ))

    # ---------------------------------------------------------
    # 3. Evidence and integrity metadata
    # ---------------------------------------------------------
    _section("2. Evidence Inventory and Integrity Metadata", styles, story)

    if not evidence_items:
        story.append(Paragraph(
            "No evidence records were returned for this report.",
            styles["ReportBody"],
        ))

    for index, item in enumerate(evidence_items, start=1):
        story.append(Paragraph(
            f"Evidence Item {index}: "
            f"{escape(_text(item.get('filename')))}",
            styles["SubsectionHeading"],
        ))

        evidence_rows = [
            [
                _paragraph("Field", styles["TableCell"]),
                _paragraph("Recorded value", styles["TableCell"]),
            ]
        ]

        for label, key in [
            ("Evidence ID", "id"),
            ("Original filename", "filename"),
            ("SHA-256", "sha256"),
            ("Size in bytes", "size_bytes"),
            ("Content type", "content_type"),
            ("Created / uploaded", "created_at"),
        ]:
            value = item.get(key)
            if key == "created_at":
                value = _timestamp(value)

            evidence_rows.append([
                _paragraph(label, styles["TableCell"]),
                _paragraph(value, styles["TableCell"]),
            ])

        story.append(_make_table(
            evidence_rows,
            [42 * mm, 128 * mm],
            colors,
            styles,
        ))
        story.append(Spacer(1, 7))

    # ---------------------------------------------------------
    # 4. Detection findings
    # ---------------------------------------------------------
    _section("3. Detection Findings", styles, story)

    if not detections:
        story.append(Paragraph(
            "No detection records were returned for the selected scope.",
            styles["ReportBody"],
        ))

    for index, item in enumerate(detections, start=1):
        title = _text(item.get("title"), "Untitled detection")
        severity = _text(item.get("severity"), "Unknown").upper()

        heading = Paragraph(
            f"{index}. [{escape(severity)}] {escape(title)}",
            styles["SubsectionHeading"],
        )

        detail_rows = [
            [
                _paragraph("Field", styles["TableCell"]),
                _paragraph("Recorded value", styles["TableCell"]),
            ]
        ]

        fields = [
            ("Detection ID", "id"),
            ("Evidence ID", "evidence_id"),
            ("Detection type", "detection_type"),
            ("Timestamp", "timestamp"),
            ("Source IP", "source_ip"),
            ("Destination IP", "destination_ip"),
            ("Confidence", "confidence"),
        ]

        for label, key in fields:
            value = item.get(key)
            if key == "timestamp":
                value = _timestamp(value)

            if value is not None:
                detail_rows.append([
                    _paragraph(label, styles["TableCell"]),
                    _paragraph(value, styles["TableCell"]),
                ])

        group = [heading]

        if item.get("description"):
            group.append(_paragraph(
                item["description"],
                styles["ReportBody"],
            ))

        group.append(_make_table(
            detail_rows,
            [42 * mm, 128 * mm],
            colors,
            styles,
        ))
        group.append(Spacer(1, 6))

        story.append(KeepTogether(group))

    # ---------------------------------------------------------
    # 5. IOC inventory
    # ---------------------------------------------------------
    story.append(PageBreak())
    _section("4. Indicator of Compromise (IOC) Inventory", styles, story)

    if iocs:
        ioc_rows = [[
            _paragraph("Type", styles["TableCell"]),
            _paragraph("Indicator value", styles["TableCell"]),
            _paragraph("Source", styles["TableCell"]),
            _paragraph("Severity", styles["TableCell"]),
            _paragraph("Occurrences / confidence", styles["TableCell"]),
        ]]

        for item in iocs:
            occurrence_text = (
                f"Occurrences: {_text(item.get('occurrences'))}\n"
                f"Confidence: {_text(item.get('confidence'))}"
            )

            ioc_rows.append([
                _paragraph(item.get("ioc_type"), styles["TableCell"]),
                _paragraph(item.get("value"), styles["TableCell"]),
                _paragraph(item.get("source"), styles["TableCell"]),
                _paragraph(item.get("severity"), styles["TableCell"]),
                _paragraph(occurrence_text, styles["TableCell"]),
            ])

        story.append(_make_table(
            ioc_rows,
            [27 * mm, 54 * mm, 30 * mm, 22 * mm, 37 * mm],
            colors,
            styles,
        ))
    else:
        story.append(Paragraph(
            "No IOC records were returned for the selected scope.",
            styles["ReportBody"],
        ))

    story.append(Paragraph(
        "IOC values should be validated against their context, timestamps, "
        "source data, and trusted threat-intelligence sources before being "
        "used for blocking or attribution.",
        styles["ReportBody"],
    ))

    # ---------------------------------------------------------
    # 6. Timeline
    # ---------------------------------------------------------
    story.append(PageBreak())
    _section("5. Investigation Timeline", styles, story)

    if timeline:
        timeline_rows = [[
            _paragraph("Timestamp", styles["TableCell"]),
            _paragraph("Event type", styles["TableCell"]),
            _paragraph("Severity", styles["TableCell"]),
            _paragraph("Title", styles["TableCell"]),
            _paragraph("Description", styles["TableCell"]),
        ]]

        for item in timeline:
            timeline_rows.append([
                _paragraph(
                    _timestamp(item.get("timestamp")),
                    styles["TableCell"],
                ),
                _paragraph(item.get("event_type"), styles["TableCell"]),
                _paragraph(item.get("severity"), styles["TableCell"]),
                _paragraph(item.get("title"), styles["TableCell"]),
                _paragraph(item.get("description"), styles["TableCell"]),
            ])

        story.append(_make_table(
            timeline_rows,
            [32 * mm, 27 * mm, 20 * mm, 40 * mm, 51 * mm],
            colors,
            styles,
        ))
    else:
        story.append(Paragraph(
            "No timeline events were returned for the selected scope.",
            styles["ReportBody"],
        ))

    # ---------------------------------------------------------
    # 7. MITRE ATT&CK mappings
    # ---------------------------------------------------------
    story.append(PageBreak())
    _section("6. MITRE ATT&CK Technique Mappings", styles, story)

    if mitre:
        mitre_rows = [[
            _paragraph("Technique ID", styles["TableCell"]),
            _paragraph("Technique name", styles["TableCell"]),
            _paragraph("Tactic", styles["TableCell"]),
            _paragraph("Confidence", styles["TableCell"]),
        ]]

        for item in mitre:
            mitre_rows.append([
                _paragraph(item.get("technique_id"), styles["TableCell"]),
                _paragraph(item.get("technique_name"), styles["TableCell"]),
                _paragraph(item.get("tactic"), styles["TableCell"]),
                _paragraph(item.get("confidence"), styles["TableCell"]),
            ])

        story.append(_make_table(
            mitre_rows,
            [30 * mm, 68 * mm, 43 * mm, 29 * mm],
            colors,
            styles,
        ))
    else:
        story.append(Paragraph(
            "No MITRE ATT&CK mappings were returned for the selected scope.",
            styles["ReportBody"],
        ))

    story.append(Paragraph(
        "Technique mappings are investigative classifications. Their "
        "presence does not independently prove that a technique was "
        "successfully executed.",
        styles["ReportBody"],
    ))

    # ---------------------------------------------------------
    # 8. Analyst review and recommendations
    # ---------------------------------------------------------
    story.append(PageBreak())
    _section("7. Analyst Review and Recommended Actions", styles, story)

    recommendations = [
        (
            "Validate high-severity detections",
            "Review the supporting packets, timestamps, endpoints, ports, "
            "and detection logic. Confirm whether the activity is expected "
            "or requires escalation.",
        ),
        (
            "Investigate IOC context",
            "Correlate each relevant IP, domain, URL, or file hash with "
            "the corresponding evidence and reputable threat-intelligence "
            "sources. Do not treat an IOC match alone as proof of compromise.",
        ),
        (
            "Review event chronology",
            "Compare timeline events, flows, detections, and evidence "
            "timestamps to establish a supported sequence of activity.",
        ),
        (
            "Preserve evidence",
            "Retain the original capture and its recorded hash. Verify "
            "the original evidence independently when integrity validation "
            "is required, and document the method and result.",
        ),
        (
            "Document conclusions",
            "Record the evidence supporting each conclusion, alternative "
            "explanations, unresolved questions, and any additional "
            "collection or containment actions taken.",
        ),
    ]

    for title, description in recommendations:
        story.append(Paragraph(
            escape(title),
            styles["SubsectionHeading"],
        ))
        story.append(_paragraph(description, styles["ReportBody"]))

    _section("8. Report Limitations", styles, story)

    for limitation in limitations:
        story.append(Paragraph(
            "• " + escape(_text(limitation)),
            styles["ReportBody"],
        ))

    additional_limitations = [
        "This PDF includes the report-generator fields available at export "
        "time. It does not include full flow records or analysis sections "
        "that are not returned by the report generator.",
        "AI incident reasoning, recovered-file details, protocol-specific "
        "DNS/HTTP/TLS findings, and raw packet evidence are not independently "
        "reconstructed by this PDF exporter.",
        "A file identified by a signature or metadata heuristic is not "
        "thereby proven malicious, executed, or attributed to a threat actor.",
    ]

    for limitation in additional_limitations:
        story.append(Paragraph(
            "• " + escape(limitation),
            styles["ReportBody"],
        ))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "END OF REPORT",
        ParagraphStyle(
            "EndOfReport",
            parent=styles["Normal"],
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.HexColor("#526078"),
            spaceBefore=8,
        ),
    ))

    doc.build(
        story,
        onFirstPage=_page_footer,
        onLaterPages=_page_footer,
    )

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="netforensicx-report-{case_id}.pdf"'
            )
        },
    )
