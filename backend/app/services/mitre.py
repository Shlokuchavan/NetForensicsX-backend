from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.data.mitre_techniques import MITRE_TECHNIQUES
from app.models.detection import Detection
from app.models.mitre_mapping import MitreMapping


DETECTION_TO_TECHNIQUES = {
    "PORT_SCAN": [
        "T1046",
    ],
    "NETWORK_SCAN": [
        "T1018",
    ],
    "DNS_ANOMALY": [
        "T1071.004",
    ],
    "DNS_NXDOMAIN": [
        "T1071.004",
    ],
    "HTTP_ENUMERATION": [
        "T1071.001",
    ],
    "HTTP_ERROR": [
        "T1071.001",
    ],
    "BEACONING": [
        "T1071",
    ],
    "HIGH_VOLUME_TRAFFIC": [
        "T1041",
    ],
}


async def map_detections_to_mitre(
    db: AsyncSession,
    evidence_id: UUID,
) -> tuple[int, int]:
    detection_result = await db.execute(
        select(Detection)
        .where(
            Detection.evidence_id == evidence_id
        )
    )

    detections = list(
        detection_result.scalars().all()
    )

    created = 0

    for detection in detections:
        techniques = DETECTION_TO_TECHNIQUES.get(
            detection.detection_type,
            [],
        )

        for technique_id in techniques:
            technique = MITRE_TECHNIQUES.get(
                technique_id
            )

            if technique is None:
                continue

            existing_result = await db.execute(
                select(MitreMapping).where(
                    MitreMapping.evidence_id == evidence_id,
                    MitreMapping.detection_id == detection.id,
                    MitreMapping.technique_id == technique_id,
                )
            )

            existing = (
                existing_result.scalar_one_or_none()
            )

            if existing:
                continue

            db.add(
                MitreMapping(
                    evidence_id=evidence_id,
                    detection_id=detection.id,
                    technique_id=technique_id,
                    technique_name=technique["name"],
                    tactic=technique["tactic"],
                    description=technique["description"],
                    confidence=detection.confidence,
                    metadata_json={
                        "detection_type": detection.detection_type,
                        "detection_title": detection.title,
                    },
                )
            )

            created += 1

    if created:
        await db.commit()

    result = await db.execute(
        select(MitreMapping)
        .where(
            MitreMapping.evidence_id == evidence_id
        )
    )

    total = len(
        list(result.scalars().all())
    )

    return created, total