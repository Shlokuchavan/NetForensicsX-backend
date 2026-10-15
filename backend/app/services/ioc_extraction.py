from collections import defaultdict
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns_record import DNSRecord
from app.models.http_transaction import HTTPTransaction
from app.models.ioc import IOC
from app.models.network_flow import NetworkFlow
from app.models.tls_session import TLSSession


def add_observation(
    store: dict[tuple[str, str], dict],
    ioc_type: str,
    value: str,
    source: str,
    timestamp: float | None,
):
    if not value:
        return

    value = value.strip()

    if not value:
        return

    key = (
        ioc_type,
        value.lower(),
    )

    item = store.get(key)

    if item is None:
        store[key] = {
            "ioc_type": ioc_type,
            "value": value,
            "source": source,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "occurrences": 1,
        }
        return

    item["occurrences"] += 1

    if timestamp is not None:
        if (
            item["first_seen"] is None
            or timestamp < item["first_seen"]
        ):
            item["first_seen"] = timestamp

        if (
            item["last_seen"] is None
            or timestamp > item["last_seen"]
        ):
            item["last_seen"] = timestamp


async def extract_iocs(
    db: AsyncSession,
    evidence_id: UUID,
) -> tuple[int, int]:
    store: dict[tuple[str, str], dict] = {}

    flows_result = await db.execute(
        select(NetworkFlow)
        .where(NetworkFlow.evidence_id == evidence_id)
    )

    for flow in flows_result.scalars().all():
        timestamp = flow.first_seen

        add_observation(
            store,
            "IP",
            flow.source_ip,
            "flow",
            timestamp,
        )

        add_observation(
            store,
            "IP",
            flow.destination_ip,
            "flow",
            timestamp,
        )

    dns_result = await db.execute(
        select(DNSRecord)
        .where(DNSRecord.evidence_id == evidence_id)
    )

    for record in dns_result.scalars().all():
        add_observation(
            store,
            "DOMAIN",
            record.query_name,
            "dns",
            record.timestamp,
        )

        if record.answers:
            for answer in record.answers.split(","):
                answer = answer.strip()

                if answer:
                    add_observation(
                        store,
                        "IP",
                        answer,
                        "dns_answer",
                        record.timestamp,
                    )

    http_result = await db.execute(
        select(HTTPTransaction)
        .where(HTTPTransaction.evidence_id == evidence_id)
    )

    for record in http_result.scalars().all():
        add_observation(
            store,
            "IP",
            record.source_ip,
            "http",
            record.timestamp,
        )

        add_observation(
            store,
            "IP",
            record.destination_ip,
            "http",
            record.timestamp,
        )

        add_observation(
            store,
            "DOMAIN",
            record.host,
            "http_host",
            record.timestamp,
        )

        if record.host and record.uri:
            uri = record.uri

            if uri.startswith("http://") or uri.startswith("https://"):
                url = uri
            else:
                scheme = (
                    "https"
                    if record.destination_port == 443
                    else "http"
                )

                url = f"{scheme}://{record.host}{uri}"

            add_observation(
                store,
                "URL",
                url,
                "http",
                record.timestamp,
            )

        add_observation(
            store,
            "USER_AGENT",
            record.user_agent,
            "http",
            record.timestamp,
        )

    tls_result = await db.execute(
        select(TLSSession)
        .where(TLSSession.evidence_id == evidence_id)
    )

    for record in tls_result.scalars().all():
        add_observation(
            store,
            "IP",
            record.source_ip,
            "tls",
            record.timestamp,
        )

        add_observation(
            store,
            "IP",
            record.destination_ip,
            "tls",
            record.timestamp,
        )

        add_observation(
            store,
            "DOMAIN",
            record.sni,
            "tls_sni",
            record.timestamp,
        )

    created = 0
    updated = 0

    for item in store.values():
        result = await db.execute(
            select(IOC).where(
                IOC.evidence_id == evidence_id,
                IOC.ioc_type == item["ioc_type"],
                IOC.value == item["value"],
            )
        )

        existing = result.scalar_one_or_none()

        if existing:
            existing.occurrences = item["occurrences"]

            existing.first_seen = item["first_seen"]
            existing.last_seen = item["last_seen"]

            updated += 1
            continue

        severity = "info"
        confidence = 0.50

        if item["ioc_type"] == "URL":
            confidence = 0.65

        elif item["ioc_type"] == "DOMAIN":
            confidence = 0.60

        elif item["ioc_type"] == "USER_AGENT":
            confidence = 0.40

        db.add(
            IOC(
                evidence_id=evidence_id,
                ioc_type=item["ioc_type"],
                value=item["value"],
                source=item["source"],
                first_seen=item["first_seen"],
                last_seen=item["last_seen"],
                occurrences=item["occurrences"],
                confidence=confidence,
                severity=severity,
                metadata_json={},
            )
        )

        created += 1

    await db.commit()

    result = await db.execute(
        select(IOC).where(
            IOC.evidence_id == evidence_id
        )
    )

    total = len(
        list(result.scalars().all())
    )

    return created, updated