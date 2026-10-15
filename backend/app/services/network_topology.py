from collections import defaultdict
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network_flow import NetworkFlow


async def build_network_topology(
    db: AsyncSession,
    evidence_id: UUID,
):
    result = await db.execute(
        select(NetworkFlow)
        .where(
            NetworkFlow.evidence_id == evidence_id
        )
    )

    flows = list(result.scalars().all())

    nodes: dict[str, dict] = {}

    edges: list[dict] = []

    for flow in flows:
        source = flow.source_ip
        target = flow.destination_ip

        if source not in nodes:
            nodes[source] = {
                "id": source,
                "label": source,
                "packets": 0,
                "bytes": 0,
                "connections": 0,
            }

        if target not in nodes:
            nodes[target] = {
                "id": target,
                "label": target,
                "packets": 0,
                "bytes": 0,
                "connections": 0,
            }

        packets = flow.packets or 0
        bytes_count = flow.bytes or 0

        nodes[source]["packets"] += packets
        nodes[source]["bytes"] += bytes_count

        nodes[target]["packets"] += packets
        nodes[target]["bytes"] += bytes_count

        nodes[source]["connections"] += 1
        nodes[target]["connections"] += 1

        edges.append(
            {
                "id": str(flow.id),
                "source": source,
                "target": target,
                "protocol": flow.protocol,
                "source_port": flow.source_port,
                "destination_port": flow.destination_port,
                "packets": packets,
                "bytes": bytes_count,
            }
        )

    return {
        "evidence_id": str(evidence_id),
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }