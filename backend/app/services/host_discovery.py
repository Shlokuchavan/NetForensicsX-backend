from collections import defaultdict
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network_flow import NetworkFlow
from app.models.network_host import NetworkHost


async def discover_hosts(
    db: AsyncSession,
    evidence_id: UUID,
) -> list[NetworkHost]:
    """
    Build host-level statistics from aggregated network flows.

    The network_flows table is treated as the source for host
    discovery so the original PCAP does not need to be reparsed.
    """

    result = await db.execute(
        select(NetworkFlow)
        .where(
            NetworkFlow.evidence_id == evidence_id
        )
    )

    flows = list(result.scalars().all())

    if not flows:
        await db.execute(
            delete(NetworkHost).where(
                NetworkHost.evidence_id == evidence_id
            )
        )

        await db.commit()

        return []

    hosts: dict[str, dict] = defaultdict(
        lambda: {
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "destinations": set(),
            "sources": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    for flow in flows:
        source = flow.source_ip
        destination = flow.destination_ip

        packets = flow.packets or 0
        bytes_count = flow.bytes or 0

        hosts[source]["packets_sent"] += packets
        hosts[source]["bytes_sent"] += bytes_count

        hosts[source]["destinations"].add(
            destination
        )

        hosts[destination]["packets_received"] += packets
        hosts[destination]["bytes_received"] += bytes_count

        hosts[destination]["sources"].add(
            source
        )

        if flow.first_seen is not None:
            current_first = hosts[source]["first_seen"]

            if (
                current_first is None
                or flow.first_seen < current_first
            ):
                hosts[source]["first_seen"] = (
                    flow.first_seen
                )

            current_destination_first = hosts[destination][
                "first_seen"
            ]

            if (
                current_destination_first is None
                or flow.first_seen < current_destination_first
            ):
                hosts[destination]["first_seen"] = (
                    flow.first_seen
                )

        if flow.last_seen is not None:
            current_last = hosts[source]["last_seen"]

            if (
                current_last is None
                or flow.last_seen > current_last
            ):
                hosts[source]["last_seen"] = (
                    flow.last_seen
                )

            current_destination_last = hosts[destination][
                "last_seen"
            ]

            if (
                current_destination_last is None
                or flow.last_seen > current_destination_last
            ):
                hosts[destination]["last_seen"] = (
                    flow.last_seen
                )

    await db.execute(
        delete(NetworkHost).where(
            NetworkHost.evidence_id == evidence_id
        )
    )

    discovered_hosts: list[NetworkHost] = []

    for ip_address, data in hosts.items():
        host = NetworkHost(
            evidence_id=evidence_id,
            ip_address=ip_address,
            packets_sent=data["packets_sent"],
            packets_received=data["packets_received"],
            bytes_sent=data["bytes_sent"],
            bytes_received=data["bytes_received"],
            unique_destinations=len(
                data["destinations"]
            ),
            unique_sources=len(
                data["sources"]
            ),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
        )

        db.add(host)

        discovered_hosts.append(host)

    await db.commit()

    for host in discovered_hosts:
        await db.refresh(host)

    return discovered_hosts