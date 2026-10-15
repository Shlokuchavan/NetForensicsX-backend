# backend/app/services/flow_intelligence.py

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network_flow import NetworkFlow


def _value(obj: Any, *names: str, default=None):
    """Read a model field while tolerating common field-name variations."""
    for name in names:
        try:
            value = getattr(obj, name, None)
            if value is not None:
                return value
        except Exception:
            pass
    return default


def _number(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0


def _timestamp(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def serialize_flow(flow: NetworkFlow) -> dict:
    source_ip = _value(flow, "source_ip", "src_ip", "src")
    destination_ip = _value(
        flow, "destination_ip", "dest_ip", "dst_ip", "dst"
    )
    source_port = _value(flow, "source_port", "src_port")
    destination_port = _value(flow, "destination_port", "dest_port", "dst_port")
    protocol = str(_value(flow, "protocol", "transport_protocol", default="OTHER")).upper()
    packets = int(_number(_value(flow, "packets", "packet_count", "total_packets")))
    byte_count = int(_number(_value(flow, "bytes", "byte_count", "total_bytes")))
    timestamp = _value(
        flow, "timestamp", "start_time", "first_seen", "time"
    )

    flags = []
    if destination_port in (22, 23, 3389, 5900):
        flags.append("remote_access_port")
    if destination_port in (4444, 5555, 6667, 31337):
        flags.append("unusual_destination_port")
    if packets > 10000:
        flags.append("high_packet_count")
    if byte_count > 100_000_000:
        flags.append("high_data_volume")
    if source_ip and destination_ip and source_ip == destination_ip:
        flags.append("same_source_destination")

    return {
        "id": str(_value(flow, "id", default="")),
        "evidence_id": str(_value(flow, "evidence_id", default="")),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packets": packets,
        "bytes": byte_count,
        "timestamp": _timestamp(timestamp),
        "duration": _number(_value(flow, "duration", "duration_seconds")),
        "suspicious": bool(flags),
        "indicators": flags,
    }


async def get_flow_intelligence(
    db: AsyncSession,
    evidence_id: str,
    *,
    protocol: str | None = None,
    search: str | None = None,
    suspicious_only: bool = False,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """Retrieve and filter network flows for one evidence item."""
    page = max(1, page)
    page_size = min(200, max(1, page_size))

    result = await db.execute(
        select(NetworkFlow).where(NetworkFlow.evidence_id == evidence_id)
    )
    flows = [serialize_flow(item) for item in result.scalars().all()]

    if protocol and protocol.upper() not in ("ALL", "ANY"):
        wanted = protocol.upper()
        flows = [item for item in flows if item["protocol"] == wanted]

    if search:
        term = search.casefold()
        flows = [
            item for item in flows
            if term in " ".join(
                str(item.get(key) or "")
                for key in (
                    "source_ip", "destination_ip", "source_port",
                    "destination_port", "protocol", "timestamp"
                )
            ).casefold()
        ]

    if suspicious_only:
        flows = [item for item in flows if item["suspicious"]]

    flows.sort(key=lambda item: item["timestamp"] or "", reverse=True)

    total = len(flows)
    start = (page - 1) * page_size
    page_items = flows[start:start + page_size]

    protocol_counts: dict[str, int] = {}
    total_bytes = 0
    total_packets = 0
    suspicious_count = 0

    for item in flows:
        name = item["protocol"]
        protocol_counts[name] = protocol_counts.get(name, 0) + 1
        total_bytes += item["bytes"]
        total_packets += item["packets"]
        suspicious_count += int(item["suspicious"])

    return {
        "items": page_items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size,
        },
        "summary": {
            "total_flows": total,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "suspicious_flows": suspicious_count,
            "protocol_counts": protocol_counts,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }