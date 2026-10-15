
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.evidence import Evidence
from app.models.http_transaction import HTTPTransaction
from app.models.ioc import IOC
from app.models.timeline_event import TimelineEvent
from app.services.file_forensics_service import analyze_file_forensics


logger = logging.getLogger(__name__)

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
}

SCRIPT_EXTENSIONS = (
    ".exe",
    ".dll",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".jar",
)


def _value(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def _as_text(value: Any) -> str:
    return str(value) if value is not None else ""


def _severity_rank(value: Any) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }.get(_as_text(value).strip().lower(), 0)


def _timestamp(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _artifact_filename(item: dict[str, Any]) -> str | None:
    value = (
        item.get("filename")
        or item.get("original_filename")
        or item.get("name")
    )
    return _as_text(value).strip() or None


def _artifact_timestamp(item: dict[str, Any]) -> float | str | None:
    value = item.get("timestamp")

    if value is None:
        return None

    numeric = _timestamp(value)

    if numeric is not None:
        return numeric

    return _as_text(value)


def _artifact_summary(item: dict[str, Any]) -> dict[str, Any]:
    """Create a compact, JSON-friendly recovered-artifact record."""
    return {
        "filename": _artifact_filename(item),
        "sha256": item.get("sha256"),
        "size_bytes": item.get("size_bytes"),
        "detected_file_type": item.get("detected_file_type"),
        "file_extension": item.get("file_extension"),
        "source_ip": item.get("source_ip"),
        "destination_ip": item.get("destination_ip"),
        "timestamp": _artifact_timestamp(item),
    }


def _recovered_file_record(
    item: dict[str, Any],
) -> dict[str, Any]:
    """Build the complete recovered-file record for the API."""
    return {
        "artifact_id": item.get("artifact_id"),
        "filename": _artifact_filename(item),
        "recovered": item.get("recovered"),
        "suspicious": item.get("suspicious"),
        "suspicious_reasons": item.get("suspicious_reasons") or [],
        "sha256": item.get("sha256"),
        "size_bytes": item.get("size_bytes"),
        "file_extension": item.get("file_extension"),
        "declared_mime_type": item.get("declared_mime_type"),
        "detected_file_type": item.get("detected_file_type"),
        "source_ip": item.get("source_ip"),
        "destination_ip": item.get("destination_ip"),
        "http_status": item.get("http_status"),
        "timestamp": _artifact_timestamp(item),
    }


async def build_incident_reasoning(
    db: AsyncSession,
    case_id: UUID,
    evidence_id: UUID,
) -> dict[str, Any]:
    """
    Correlate detections, IOCs, HTTP metadata, timeline events,
    and recovered files for a single evidence item.

    This is deterministic evidence correlation. It does not invoke
    an external AI model or prove that a recovered file is malicious.
    """

    # ---------------------------------------------------------
    # 1. Validate evidence ownership
    # ---------------------------------------------------------

    evidence = await db.get(Evidence, evidence_id)

    if evidence is None or evidence.case_id != case_id:
        raise ValueError("Evidence not found in this case")

    # ---------------------------------------------------------
    # 2. Load detection records
    # ---------------------------------------------------------

    detection_result = await db.execute(
        select(Detection)
        .where(Detection.evidence_id == evidence_id)
        .order_by(Detection.timestamp.asc().nullslast())
        .limit(1000)
    )
    detections = list(detection_result.scalars().all())

    # ---------------------------------------------------------
    # 3. Load IOC records
    # ---------------------------------------------------------

    ioc_result = await db.execute(
        select(IOC)
        .where(IOC.evidence_id == evidence_id)
        .order_by(IOC.occurrences.desc())
        .limit(1000)
    )
    iocs = list(ioc_result.scalars().all())

    # ---------------------------------------------------------
    # 4. Load HTTP transaction metadata
    # ---------------------------------------------------------

    http_result = await db.execute(
        select(HTTPTransaction)
        .where(HTTPTransaction.evidence_id == evidence_id)
        .order_by(HTTPTransaction.timestamp.asc().nullslast())
        .limit(2000)
    )
    http_rows = list(http_result.scalars().all())

    # ---------------------------------------------------------
    # 5. Run the existing File Forensics service
    #
    # HTTPTransaction stores metadata, not reconstructed
    # response-body bytes. File Forensics is the source of
    # recovered-file artifacts for this assessment.
    # ---------------------------------------------------------

    file_forensics_warnings: list[str] = []
    file_forensics_result: dict[str, Any] = {"artifacts": []}

    try:
        result = await analyze_file_forensics(
            db=db,
            case_id=case_id,
            evidence_id=evidence_id,
        )

        if isinstance(result, dict):
            file_forensics_result = result
        else:
            file_forensics_warnings.append(
                "File-forensics returned an unexpected result format."
            )

    except Exception:
        logger.exception(
            "File-forensics failed during incident reasoning "
            "for evidence %s",
            evidence_id,
        )
        file_forensics_warnings.append(
            "File-forensics analysis could not be completed during "
            "incident reasoning. Run File Forensics separately."
        )

    raw_artifacts = file_forensics_result.get("artifacts", [])

    if not isinstance(raw_artifacts, list):
        raw_artifacts = []
        file_forensics_warnings.append(
            "File-forensics returned an invalid artifacts collection."
        )

    file_artifacts = [
        item
        for item in raw_artifacts
        if isinstance(item, dict)
    ]

    recovered_artifacts = [
        item
        for item in file_artifacts
        if item.get("recovered") is True
    ]

    executable_artifacts = [
        item
        for item in recovered_artifacts
        if (
            "portable-executable"
            in _as_text(item.get("detected_file_type")).lower()
            or _as_text(item.get("file_extension")).lower()
            in EXECUTABLE_EXTENSIONS
        )
    ]

    suspicious_recovered_artifacts = [
        item
        for item in recovered_artifacts
        if item.get("suspicious") is True
    ]

    # ---------------------------------------------------------
    # 6. Load timeline events
    # ---------------------------------------------------------

    timeline_result = await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.evidence_id == evidence_id)
        .order_by(TimelineEvent.timestamp.asc().nullslast())
        .limit(2000)
    )
    timeline_rows = list(timeline_result.scalars().all())

    # ---------------------------------------------------------
    # 7. Calculate detection and HTTP statistics
    # ---------------------------------------------------------

    severity_counts = Counter(
        _as_text(_value(row, "severity", "unknown"))
        .strip()
        .lower()
        or "unknown"
        for row in detections
    )

    detection_ips: Counter[str] = Counter()

    for row in detections:
        for field in ("source_ip", "destination_ip"):
            ip = _as_text(_value(row, field)).strip()

            if ip:
                detection_ips[ip] += 1

    http_hosts = Counter(
        _as_text(_value(row, "host")).strip()
        for row in http_rows
        if _value(row, "host")
    )

    http_destinations = Counter(
        _as_text(_value(row, "destination_ip")).strip()
        for row in http_rows
        if _value(row, "destination_ip")
    )

    ioc_values = {
        _as_text(_value(row, "value")).strip().lower(): row
        for row in iocs
        if _value(row, "value")
        and _as_text(_value(row, "value")).strip()
    }

    # ---------------------------------------------------------
    # 8. Correlate HTTP metadata with IOCs
    # ---------------------------------------------------------

    matched_iocs: list[dict[str, Any]] = []

    for tx in http_rows:
        candidates = [
            _as_text(_value(tx, "host")).strip(),
            _as_text(_value(tx, "uri")).strip(),
            _as_text(_value(tx, "destination_ip")).strip(),
        ]

        searchable = " ".join(candidates).lower()

        for value, ioc in ioc_values.items():
            if value not in searchable:
                continue

            matched_iocs.append({
                "ioc_type": _value(ioc, "ioc_type"),
                "value": _value(ioc, "value"),
                "severity": _value(ioc, "severity"),
                "confidence": _value(ioc, "confidence"),
                "http_host": _value(tx, "host"),
                "http_uri": _value(tx, "uri"),
                "destination_ip": _value(tx, "destination_ip"),
                "timestamp": _timestamp(
                    _value(tx, "timestamp")
                ),
                "reason": (
                    "IOC value appears in HTTP host, URI, "
                    "or destination IP."
                ),
            })

    matched_iocs = matched_iocs[:100]

    # ---------------------------------------------------------
    # 9. Normalize and sort timeline records
    # ---------------------------------------------------------

    timeline: list[dict[str, Any]] = []

    for row in timeline_rows:
        timeline.append({
            "timestamp": _timestamp(_value(row, "timestamp")),
            "event_type": _value(row, "event_type"),
            "title": _value(row, "title"),
            "description": _value(row, "description"),
            "severity": _value(row, "severity"),
            "source_ip": _value(row, "source_ip"),
            "destination_ip": _value(row, "destination_ip"),
            "reference_type": _value(row, "reference_type"),
            "reference_id": _value(row, "reference_id"),
        })

    timeline.sort(
        key=lambda row: (
            row["timestamp"] is None,
            row["timestamp"] if row["timestamp"] is not None else 0,
        )
    )

    # ---------------------------------------------------------
    # 10. Normalize detections
    # ---------------------------------------------------------

    detection_items = [
        {
            "timestamp": _timestamp(_value(row, "timestamp")),
            "title": _value(row, "title"),
            "description": _value(row, "description"),
            "severity": _value(row, "severity"),
            "detection_type": _value(row, "detection_type"),
            "source_ip": _value(row, "source_ip"),
            "destination_ip": _value(row, "destination_ip"),
            "status": _value(row, "status"),
        }
        for row in detections
    ]

    # ---------------------------------------------------------
    # 11. Normalize HTTP transactions
    # ---------------------------------------------------------

    http_items = [
        {
            "timestamp": _timestamp(_value(row, "timestamp")),
            "source_ip": _value(row, "source_ip"),
            "destination_ip": _value(row, "destination_ip"),
            "source_port": _value(row, "source_port"),
            "destination_port": _value(row, "destination_port"),
            "method": _value(row, "method"),
            "host": _value(row, "host"),
            "uri": _value(row, "uri"),
            "status_code": _value(row, "status_code"),
            "user_agent": _value(row, "user_agent"),
        }
        for row in http_rows
    ]

    # ---------------------------------------------------------
    # 12. Identify high-severity detections and IOCs
    # ---------------------------------------------------------

    high_detections = [
        row
        for row in detections
        if _severity_rank(_value(row, "severity")) >= 4
    ]

    critical_or_high_iocs = [
        row
        for row in iocs
        if _severity_rank(_value(row, "severity")) >= 4
    ]

    # ---------------------------------------------------------
    # 13. Identify HTTP URIs that reference executable/scripts
    #
    # This is supplementary evidence only. Recovered files are
    # tracked independently of HTTP transaction availability.
    # ---------------------------------------------------------

    suspicious_downloads: list[dict[str, Any]] = []

    for row in http_rows:
        uri = _as_text(_value(row, "uri"))
        lowered = uri.lower().split("?", 1)[0].split("#", 1)[0]

        if not any(
            lowered.endswith(extension)
            for extension in SCRIPT_EXTENSIONS
        ):
            continue

        suspicious_downloads.append({
            "timestamp": _timestamp(_value(row, "timestamp")),
            "host": _value(row, "host"),
            "uri": uri,
            "source_ip": _value(row, "source_ip"),
            "destination_ip": _value(row, "destination_ip"),
            "status_code": _value(row, "status_code"),
            "reason": (
                "HTTP URI ends in an executable or script extension. "
                "This does not establish complete transfer, file contents, "
                "or execution."
            ),
        })

    # ---------------------------------------------------------
    # 14. Build the incident narrative
    # ---------------------------------------------------------

    narrative: list[dict[str, Any]] = []

    if high_detections:
        narrative.append({
            "stage": "Detection evidence",
            "finding": (
                f"{len(high_detections)} high/critical detection(s) "
                "were recorded for this evidence."
            ),
            "confidence": "high",
            "basis": [
                _value(row, "title", "Detection")
                for row in high_detections[:10]
            ],
            "caveat": (
                "Severity reflects the configured detection rule. "
                "It is not independent proof of compromise."
            ),
        })

    elif detections:
        narrative.append({
            "stage": "Detection evidence",
            "finding": (
                f"{len(detections)} detection(s) were recorded, "
                "but none was classified high or critical."
            ),
            "confidence": "high",
            "basis": ["Existing Detection records"],
            "caveat": (
                "Lower severity does not prove the activity is benign."
            ),
        })

    else:
        narrative.append({
            "stage": "Detection evidence",
            "finding": "No Detection records were found for this evidence.",
            "confidence": "high",
            "basis": [],
            "caveat": (
                "Rules may not have run, or the available data may not "
                "have matched existing rules."
            ),
        })

    # Correlate recovered files even when http_rows is empty.
    if recovered_artifacts:
        narrative.append({
            "stage": "Recovered payload evidence",
            "finding": (
                f"{len(recovered_artifacts)} file artifact(s) were "
                f"reconstructed from the PCAP, including "
                f"{len(executable_artifacts)} detected executable(s)."
            ),
            "confidence": "high",
            "basis": [
                _artifact_summary(item)
                for item in recovered_artifacts[:20]
            ],
            "caveat": (
                "Recovery establishes that the file-forensics analyzer "
                "reconstructed artifact bytes from the capture. An "
                "executable file type does not establish maliciousness "
                "or execution. Validate hashes and transfer context."
            ),
        })

    if suspicious_recovered_artifacts:
        narrative.append({
            "stage": "Suspicious recovered artifacts",
            "finding": (
                f"{len(suspicious_recovered_artifacts)} recovered "
                "artifact(s) were marked suspicious by File Forensics."
            ),
            "confidence": "medium",
            "basis": [
                {
                    "filename": _artifact_filename(item),
                    "sha256": item.get("sha256"),
                    "suspicious_reasons": (
                        item.get("suspicious_reasons") or []
                    ),
                }
                for item in suspicious_recovered_artifacts[:20]
            ],
            "caveat": (
                "This classification comes from the file-forensics "
                "analyzer and requires independent validation."
            ),
        })

    if file_forensics_warnings:
        narrative.append({
            "stage": "File-forensics availability",
            "finding": (
                "File-forensics analysis was incomplete during "
                "incident reasoning."
            ),
            "confidence": "low",
            "basis": file_forensics_warnings[:10],
            "caveat": (
                "Incomplete analysis or an empty result does not establish "
                "that the PCAP contains no transferred files."
            ),
        })

    if suspicious_downloads:
        narrative.append({
            "stage": "Possible payload transfer",
            "finding": (
                f"{len(suspicious_downloads)} HTTP transaction(s) "
                "reference an executable or script filename."
            ),
            "confidence": "medium",
            "basis": [
                f"{item.get('host') or 'unknown host'}"
                f"{item.get('uri') or ''}"
                for item in suspicious_downloads[:10]
            ],
            "caveat": (
                "URI extensions alone do not verify file contents, "
                "successful transfer, or execution."
            ),
        })

    if matched_iocs:
        narrative.append({
            "stage": "IOC correlation",
            "finding": (
                f"{len(matched_iocs)} HTTP-to-IOC correlation(s) "
                "were found."
            ),
            "confidence": "medium",
            "basis": [
                f"{item['ioc_type']}: {item['value']}"
                for item in matched_iocs[:10]
            ],
            "caveat": (
                "This uses substring matching against HTTP host, URI, "
                "and destination IP. Validate the context and freshness "
                "of each indicator."
            ),
        })

    else:
        narrative.append({
            "stage": "IOC correlation",
            "finding": "No HTTP-to-IOC matches were identified.",
            "confidence": "medium",
            "basis": [],
            "caveat": (
                "This does not establish benign traffic. HTTP metadata "
                "or IOC coverage may be incomplete."
            ),
        })

    most_common_ips = detection_ips.most_common(10)

    if most_common_ips:
        narrative.append({
            "stage": "Address correlation",
            "finding": (
                "These IP addresses recur in detection "
                "source/destination fields."
            ),
            "confidence": "medium",
            "basis": [
                {
                    "ip": ip,
                    "detection_references": count,
                }
                for ip, count in most_common_ips
            ],
            "caveat": (
                "IP frequency does not establish attacker identity, "
                "compromise, or the role of a particular machine."
            ),
        })

    # ---------------------------------------------------------
    # 15. Generate recommended investigation steps
    # ---------------------------------------------------------

    recommended_steps: list[str] = []

    if not detections:
        recommended_steps.append(
            "Run existing detection analysis for this evidence "
            "and review its output."
        )

    if not iocs:
        recommended_steps.append(
            "Run IOC extraction and validate the extracted indicators."
        )

    if suspicious_downloads:
        recommended_steps.append(
            "Inspect HTTP status codes, file signatures, recovered "
            "artifact hashes, and transfer context."
        )

        recommended_steps.append(
            "Review endpoint process-creation and file-write telemetry "
            "before concluding that a recovered file executed."
        )

    if recovered_artifacts:
        recommended_steps.append(
            "Validate each recovered file's SHA-256 and PE signature, "
            "then correlate its transfer time and endpoints with DNS, "
            "network flows, and available endpoint process/file telemetry."
        )

    if suspicious_recovered_artifacts:
        recommended_steps.append(
            "Prioritize suspicious recovered artifacts for isolated "
            "static analysis and trusted reputation checks."
        )

    if matched_iocs:
        recommended_steps.append(
            "Review each IOC's source, confidence, and first/last-seen "
            "context before escalation."
        )

    if not timeline_rows:
        recommended_steps.append(
            "Generate or review the evidence timeline to establish "
            "event ordering."
        )

    if file_forensics_warnings:
        recommended_steps.append(
            "Run File Forensics separately and verify whether artifact "
            "reconstruction completed successfully."
        )

    recommended_steps.extend([
        (
            "Validate source/destination roles using packet direction, "
            "DNS/DHCP context, network flows, and known asset ownership."
        ),
        (
            "Preserve the original PCAP and record cryptographic hashes "
            "of extracted artifacts."
        ),
    ])

    # ---------------------------------------------------------
    # 16. Calculate observed timestamp range
    # ---------------------------------------------------------

    all_timestamps = [
        _timestamp(_value(row, "timestamp"))
        for row in detections + http_rows
    ]

    known_timestamps = [
        value
        for value in all_timestamps
        if value is not None
    ]

    # ---------------------------------------------------------
    # 17. Conservative overall confidence
    #
    # This is a heuristic for evidence corroboration, not a
    # probability of compromise or attacker attribution.
    # ---------------------------------------------------------

    overall_confidence = "low"

    if detections and timeline_rows:
        overall_confidence = "medium"

    if (
        high_detections
        and matched_iocs
        and timeline_rows
    ):
        overall_confidence = "high"

    # ---------------------------------------------------------
    # 18. Serialize recovered artifacts
    # ---------------------------------------------------------

    recovered_file_artifacts = [
        _recovered_file_record(item)
        for item in recovered_artifacts
    ]

    # ---------------------------------------------------------
    # 19. Return the complete assessment
    # ---------------------------------------------------------

    return {
        "case_id": str(case_id),
        "evidence_id": str(evidence_id),
        "evidence_filename": _value(
            evidence,
            "original_filename",
        ),
        "analysis_type": "deterministic_evidence_correlation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_confidence": overall_confidence,
        "summary": (
            f"Reviewed {len(detections)} detection(s), "
            f"{len(iocs)} IOC(s), "
            f"{len(http_rows)} HTTP transaction(s), "
            f"{len(timeline_rows)} timeline event(s), and "
            f"{len(recovered_artifacts)} recovered file artifact(s)."
        ),
        "statistics": {
            "detections": len(detections),
            "high_or_critical_detections": len(high_detections),
            "severity_counts": dict(severity_counts),
            "iocs": len(iocs),
            "high_or_critical_iocs": len(critical_or_high_iocs),
            "http_transactions": len(http_rows),
            "timeline_events": len(timeline_rows),
            "http_ioc_matches": len(matched_iocs),
            "executable_or_script_uri_matches": len(
                suspicious_downloads
            ),
            "unique_http_hosts": len(http_hosts),
            "unique_http_destination_ips": len(http_destinations),
            "file_artifacts_examined": len(file_artifacts),
            "recovered_files": len(recovered_artifacts),
            "recovered_executables": len(executable_artifacts),
            "suspicious_recovered_files": len(
                suspicious_recovered_artifacts
            ),
            "file_forensics_warnings": len(file_forensics_warnings),
            "earliest_observed_timestamp": (
                min(known_timestamps)
                if known_timestamps
                else None
            ),
            "latest_observed_timestamp": (
                max(known_timestamps)
                if known_timestamps
                else None
            ),
        },
        "narrative": narrative,
        "probable_sequence": timeline,
        "matched_iocs": matched_iocs,
        "suspicious_downloads": suspicious_downloads,
        "recovered_file_artifacts": recovered_file_artifacts,
        "file_forensics_warnings": file_forensics_warnings,
        "detections": detection_items,
        "http_transactions": http_items,
        "recommended_steps": _unique(recommended_steps),
        "limitations": [
            (
                "This is deterministic evidence correlation, not a claim "
                "that an external AI model was used."
            ),
            (
                "HTTPTransaction contains metadata and does not "
                "independently establish response-body contents."
            ),
            (
                "Recovered artifacts are reported separately from "
                "HTTP URI-based transfer indicators."
            ),
            (
                "Recovery of an executable does not establish "
                "maliciousness or execution."
            ),
            (
                "Beaconing and DNS detections are investigation leads; "
                "they do not independently identify a compromised host "
                "or attacker-controlled infrastructure."
            ),
            (
                "IOC substring matching can produce false positives "
                "and requires contextual validation."
            ),
            (
                "IP frequency alone does not establish attribution."
            ),
            (
                "Missing telemetry, incomplete captures, and encrypted "
                "traffic can leave the incident sequence incomplete."
            ),
            (
                "Overall confidence is a deterministic heuristic, "
                "not a calibrated probability of compromise."
            ),
        ],
    }
