# backend/app/services/network_graph.py

from collections import defaultdict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network_flow import NetworkFlow


def _get(obj, *names, default=None):
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


async def build_network_graph(
    db: AsyncSession,
    evidence_id: str,
) -> dict:
    result = await db.execute(
        select(NetworkFlow).where(NetworkFlow.evidence_id == evidence_id)
    )
    flows = result.scalars().all()

    nodes = {}
    edges = {}
    protocols = defaultdict(int)

    for flow in flows:
        src = _get(flow, "source_ip", "src_ip", "src")
        dst = _get(flow, "destination_ip", "dest_ip", "dst_ip", "dst")

        if not src or not dst:
            continue

        src, dst = str(src), str(dst)
        protocol = str(_get(flow, "protocol", default="OTHER")).upper()

        try:
            byte_count = int(
                _get(flow, "bytes", "byte_count", "total_bytes", default=0) or 0
            )
        except (ValueError, TypeError):
            byte_count = 0

        try:
            packet_count = int(
                _get(flow, "packets", "packet_count", "total_packets", default=0) or 0
            )
        except (ValueError, TypeError):
            packet_count = 0

        for ip in (src, dst):
            if ip not in nodes:
                nodes[ip] = {
                    "id": ip,
                    "label": ip,
                    "connections": 0,
                    "bytes": 0,
                    "packets": 0,
                }

        nodes[src]["connections"] += 1
        nodes[dst]["connections"] += 1
        nodes[src]["bytes"] += byte_count
        nodes[dst]["bytes"] += byte_count
        nodes[src]["packets"] += packet_count
        nodes[dst]["packets"] += packet_count

        key = (src, dst, protocol)
        if key not in edges:
            edges[key] = {
                "id": f"{src}->{dst}:{protocol}",
                "source": src,
                "target": dst,
                "protocol": protocol,
                "flow_count": 0,
                "bytes": 0,
                "packets": 0,
            }

        edges[key]["flow_count"] += 1
        edges[key]["bytes"] += byte_count
        edges[key]["packets"] += packet_count
        protocols[protocol] += 1

    return {
        "evidence_id": evidence_id,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "summary": {
            "host_count": len(nodes),
            "connection_count": len(edges),
            "flow_count": len(flows),
            "protocol_counts": dict(protocols),
        },
    }