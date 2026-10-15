# backend/app/services/report_generator.py

from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.network_flow import NetworkFlow
from app.models.detection import Detection
from app.models.ioc import IOC
from app.models.timeline_event import TimelineEvent
from app.models.mitre_mapping import MitreMapping


def _field(obj, *names, default=None):
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


def _serialize(obj, fields):
    output = {}
    for output_name, aliases in fields.items():
        value = _field(obj, *aliases)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        elif value is not None:
            value = str(value) if output_name == "id" else value
        output[output_name] = value
    return output


async def generate_forensic_report(
    db: AsyncSession,
    case_id: str,
    evidence_id: str | None = None,
) -> dict:
    case_result = await db.execute(
        select(Case).where(Case.id == case_id)
    )
    case = case_result.scalar_one_or_none()

    if case is None:
        raise ValueError("Case not found")

    evidence_query = select(Evidence).where(Evidence.case_id == case_id)
    if evidence_id:
        evidence_query = evidence_query.where(Evidence.id == evidence_id)

    evidence_result = await db.execute(evidence_query)
    evidence_items = evidence_result.scalars().all()

    if evidence_id and not evidence_items:
        raise ValueError("Evidence not found for this case")

    evidence_ids = [item.id for item in evidence_items]

    async def fetch_rows(model):
        if not evidence_ids:
            return []
        result = await db.execute(
            select(model).where(model.evidence_id.in_(evidence_ids))
        )
        return result.scalars().all()

    flows = await fetch_rows(NetworkFlow)
    detections = await fetch_rows(Detection)
    iocs = await fetch_rows(IOC)
    timeline = await fetch_rows(TimelineEvent)
    mitre = await fetch_rows(MitreMapping)

    severity_counts = {}
    for detection in detections:
        severity = str(_field(detection, "severity", default="unknown")).lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    evidence_output = []
    for item in evidence_items:
        evidence_output.append(
            _serialize(
                item,
                {
                    "id": ("id",),
                    "filename": ("original_filename", "filename", "name"),
                    "sha256": ("sha256", "file_hash", "hash"),
                    "size_bytes": ("size_bytes", "file_size", "size"),
                    "content_type": ("content_type", "mime_type"),
                    "created_at": ("created_at", "uploaded_at"),
                },
            )
        )

    return {
        "report_type": "NetForensicX Forensic Investigation Report",
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": _serialize(
            case,
            {
                "id": ("id",),
                "title": ("title", "name"),
                "description": ("description",),
                "status": ("status",),
                "created_at": ("created_at",),
                "updated_at": ("updated_at",),
            },
        ),
        "evidence": evidence_output,
        "summary": {
            "evidence_count": len(evidence_items),
            "flow_count": len(flows),
            "detection_count": len(detections),
            "ioc_count": len(iocs),
            "timeline_event_count": len(timeline),
            "mitre_mapping_count": len(mitre),
            "detections_by_severity": severity_counts,
        },
        "detections": [
            _serialize(
                item,
                {
                    "id": ("id",),
                    "evidence_id": ("evidence_id",),
                    "title": ("title",),
                    "description": ("description",),
                    "severity": ("severity",),
                    "detection_type": ("detection_type", "type"),
                    "timestamp": ("timestamp",),
                    "source_ip": ("source_ip",),
                    "destination_ip": ("destination_ip",),
                    "confidence": ("confidence",),
                },
            )
            for item in detections
        ],
        "iocs": [
            _serialize(
                item,
                {
                    "id": ("id",),
                    "evidence_id": ("evidence_id",),
                    "ioc_type": ("ioc_type", "type"),
                    "value": ("value",),
                    "source": ("source",),
                    "severity": ("severity",),
                    "confidence": ("confidence",),
                    "occurrences": ("occurrences",),
                },
            )
            for item in iocs
        ],
        "timeline": [
            _serialize(
                item,
                {
                    "id": ("id",),
                    "evidence_id": ("evidence_id",),
                    "timestamp": ("timestamp",),
                    "event_type": ("event_type",),
                    "title": ("title",),
                    "description": ("description",),
                    "severity": ("severity",),
                },
            )
            for item in timeline
        ],
        "mitre_mappings": [
            _serialize(
                item,
                {
                    "id": ("id",),
                    "technique_id": ("technique_id",),
                    "technique_name": ("technique_name",),
                    "tactic": ("tactic",),
                    "confidence": ("confidence",),
                },
            )
            for item in mitre
        ],
        "limitations": [
            "Report findings reflect records currently stored in the database.",
            "Detection indicators require analyst validation.",
            "A stored evidence hash is reported as recorded; this report does not independently re-hash the original file.",
        ],
    }