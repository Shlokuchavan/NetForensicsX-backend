import hashlib
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.dns_record import DNSRecord
from app.models.http_transaction import HTTPTransaction
from app.models.ioc import IOC
from app.models.network_flow import NetworkFlow
from app.models.timeline_event import TimelineEvent
from app.models.tls_session import TLSSession


def event_key(
    event_type: str,
    reference_id: object,
) -> str:
    return hashlib.sha256(
        f"{event_type}:{reference_id}".encode()
    ).hexdigest()


async def build_timeline(
    db: AsyncSession,
    evidence_id: UUID,
) -> tuple[int, int]:
    existing_result = await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.evidence_id == evidence_id
        )
    )

    existing = list(
        existing_result.scalars().all()
    )

    existing_keys = {
        event_key(
            row.event_type,
            row.reference_id,
        )
        for row in existing
    }

    events: list[TimelineEvent] = []

    flows_result = await db.execute(
        select(NetworkFlow)
        .where(NetworkFlow.evidence_id == evidence_id)
    )

    for flow in flows_result.scalars().all():
        if flow.first_seen is None:
            continue

        key = event_key(
            "FLOW",
            flow.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=flow.first_seen,
                event_type="FLOW",
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                title=(
                    f"{flow.protocol} network flow"
                ),
                description=(
                    f"{flow.source_ip}:"
                    f"{flow.source_port or ''} → "
                    f"{flow.destination_ip}:"
                    f"{flow.destination_port or ''}"
                ),
                severity="info",
                reference_type="network_flow",
                reference_id=str(flow.id),
                metadata_json={
                    "protocol": flow.protocol,
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                },
            )
        )

    dns_result = await db.execute(
        select(DNSRecord)
        .where(DNSRecord.evidence_id == evidence_id)
    )

    for row in dns_result.scalars().all():
        if row.timestamp is None:
            continue

        key = event_key(
            "DNS",
            row.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=row.timestamp,
                event_type="DNS",
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                title="DNS query",
                description=(
                    f"{row.query_name} "
                    f"({row.query_type or 'UNKNOWN'})"
                ),
                severity="info",
                reference_type="dns",
                reference_id=str(row.id),
                metadata_json={
                    "query_name": row.query_name,
                    "query_type": row.query_type,
                    "response_code": row.response_code,
                    "answers": row.answers,
                },
            )
        )

    http_result = await db.execute(
        select(HTTPTransaction)
        .where(HTTPTransaction.evidence_id == evidence_id)
    )

    for row in http_result.scalars().all():
        if row.timestamp is None:
            continue

        key = event_key(
            "HTTP",
            row.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=row.timestamp,
                event_type="HTTP",
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                title="HTTP transaction",
                description=(
                    f"{row.method or 'REQUEST'} "
                    f"{row.host or ''}"
                    f"{row.uri or ''}"
                ),
                severity=(
                    "medium"
                    if row.status_code in {401, 403, 404}
                    else "info"
                ),
                reference_type="http",
                reference_id=str(row.id),
                metadata_json={
                    "method": row.method,
                    "host": row.host,
                    "uri": row.uri,
                    "status_code": row.status_code,
                    "user_agent": row.user_agent,
                },
            )
        )

    tls_result = await db.execute(
        select(TLSSession)
        .where(TLSSession.evidence_id == evidence_id)
    )

    for row in tls_result.scalars().all():
        if row.timestamp is None:
            continue

        key = event_key(
            "TLS",
            row.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=row.timestamp,
                event_type="TLS",
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                title="TLS session",
                description=(
                    f"{row.tls_version or 'TLS'} "
                    f"{row.sni or 'No SNI'}"
                ),
                severity="info",
                reference_type="tls",
                reference_id=str(row.id),
                metadata_json={
                    "tls_version": row.tls_version,
                    "sni": row.sni,
                    "cipher": row.cipher,
                    "handshake_type": row.handshake_type,
                },
            )
        )

    detection_result = await db.execute(
        select(Detection)
        .where(Detection.evidence_id == evidence_id)
    )

    for row in detection_result.scalars().all():
        if row.timestamp is None:
            continue

        key = event_key(
            "DETECTION",
            row.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=row.timestamp,
                event_type="DETECTION",
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                title=row.title,
                description=row.description,
                severity=row.severity,
                reference_type="detection",
                reference_id=str(row.id),
                metadata_json=row.metadata_json,
            )
        )

    ioc_result = await db.execute(
        select(IOC)
        .where(IOC.evidence_id == evidence_id)
    )

    for row in ioc_result.scalars().all():
        if row.first_seen is None:
            continue

        key = event_key(
            "IOC",
            row.id,
        )

        if key in existing_keys:
            continue

        events.append(
            TimelineEvent(
                evidence_id=evidence_id,
                timestamp=row.first_seen,
                event_type="IOC",
                title=f"{row.ioc_type} identified",
                description=row.value,
                severity=row.severity,
                reference_type="ioc",
                reference_id=str(row.id),
                metadata_json={
                    "ioc_type": row.ioc_type,
                    "occurrences": row.occurrences,
                },
            )
        )

    for row in events:
        db.add(row)

    if events:
        await db.commit()

    total_result = await db.execute(
        select(TimelineEvent).where(
            TimelineEvent.evidence_id == evidence_id
        )
    )

    total = len(
        list(total_result.scalars().all())
    )

    return len(events), total