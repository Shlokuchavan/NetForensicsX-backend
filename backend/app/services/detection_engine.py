import hashlib
import math
from collections import defaultdict
from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.dns_record import DNSRecord
from app.models.http_transaction import HTTPTransaction
from app.models.network_flow import NetworkFlow
from app.models.tls_session import TLSSession


def fingerprint(*parts: object) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def safe_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def severity_from_score(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.50:
        return "medium"
    if score >= 0.25:
        return "low"
    return "info"


async def analyze_detections(
    db: AsyncSession,
    evidence_id: UUID,
) -> tuple[int, int]:
    result = await db.execute(
        select(Detection).where(
            Detection.evidence_id == evidence_id
        )
    )

    existing_rows = list(result.scalars().all())
    existing_fingerprints = {
        row.fingerprint for row in existing_rows
    }

    generated: list[Detection] = []

    flows_result = await db.execute(
        select(NetworkFlow)
        .where(NetworkFlow.evidence_id == evidence_id)
        .order_by(NetworkFlow.first_seen)
    )

    flows = list(flows_result.scalars().all())

    dns_result = await db.execute(
        select(DNSRecord)
        .where(DNSRecord.evidence_id == evidence_id)
        .order_by(DNSRecord.timestamp)
    )

    dns_records = list(dns_result.scalars().all())

    http_result = await db.execute(
        select(HTTPTransaction)
        .where(HTTPTransaction.evidence_id == evidence_id)
        .order_by(HTTPTransaction.timestamp)
    )

    http_records = list(http_result.scalars().all())

    tls_result = await db.execute(
        select(TLSSession)
        .where(TLSSession.evidence_id == evidence_id)
        .order_by(TLSSession.timestamp)
    )

    tls_records = list(tls_result.scalars().all())

    generated.extend(
        detect_port_scans(
            evidence_id,
            flows,
        )
    )

    generated.extend(
        detect_network_scans(
            evidence_id,
            flows,
        )
    )

    generated.extend(
        detect_dns_anomalies(
            evidence_id,
            dns_records,
        )
    )

    generated.extend(
        detect_http_anomalies(
            evidence_id,
            http_records,
        )
    )

    generated.extend(
        detect_beaconing(
            evidence_id,
            flows,
        )
    )

    generated.extend(
        detect_high_volume(
            evidence_id,
            flows,
        )
    )

    generated.extend(
        detect_rare_destinations(
            evidence_id,
            flows,
        )
    )

    new_rows = [
        row
        for row in generated
        if row.fingerprint not in existing_fingerprints
    ]

    for row in new_rows:
        db.add(row)

    if new_rows:
        await db.commit()

    return len(new_rows), len(generated) - len(new_rows)


def detect_port_scans(
    evidence_id: UUID,
    flows: list[NetworkFlow],
) -> list[Detection]:
    buckets: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)

    for flow in flows:
        if flow.source_ip and flow.destination_ip:
            buckets[
                (
                    flow.source_ip,
                    flow.destination_ip,
                )
            ].append(flow)

    detections: list[Detection] = []

    for (source_ip, destination_ip), rows in buckets.items():
        ports = {
            row.destination_port
            for row in rows
            if row.destination_port is not None
        }

        if len(ports) < 10:
            continue

        first_seen_values = [
            row.first_seen
            for row in rows
            if row.first_seen is not None
        ]

        last_seen_values = [
            row.last_seen
            for row in rows
            if row.last_seen is not None
        ]

        first_seen = min(first_seen_values) if first_seen_values else None
        last_seen = max(last_seen_values) if last_seen_values else None

        duration = (
            last_seen - first_seen
            if first_seen is not None and last_seen is not None
            else None
        )

        if duration is not None and duration > 120:
            continue

        score = min(
            1.0,
            0.50 + (len(ports) / 100.0),
        )

        severity = severity_from_score(score)

        fp = fingerprint(
            "PORT_SCAN",
            evidence_id,
            source_ip,
            destination_ip,
            sorted(ports),
        )

        detections.append(
            Detection(
                evidence_id=evidence_id,
                timestamp=first_seen,
                detection_type="PORT_SCAN",
                severity=severity,
                title="Possible TCP Port Scan",
                description=(
                    f"{source_ip} contacted {len(ports)} unique "
                    f"destination ports on {destination_ip}."
                ),
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="TCP",
                confidence=safe_confidence(score),
                status="new",
                fingerprint=fp,
                metadata_json={
                    "unique_ports": len(ports),
                    "ports": sorted(
                        p for p in ports if p is not None
                    ),
                    "duration_seconds": duration,
                },
            )
        )

    return detections


def detect_network_scans(
    evidence_id: UUID,
    flows: list[NetworkFlow],
) -> list[Detection]:
    buckets: dict[str, set[str]] = defaultdict(set)

    first_seen: dict[str, float] = {}

    for flow in flows:
        if not flow.source_ip or not flow.destination_ip:
            continue

        buckets[flow.source_ip].add(
            flow.destination_ip
        )

        if (
            flow.first_seen is not None
            and flow.source_ip not in first_seen
        ):
            first_seen[flow.source_ip] = flow.first_seen

    detections: list[Detection] = []

    for source_ip, destinations in buckets.items():
        count = len(destinations)

        if count < 10:
            continue

        score = min(
            1.0,
            0.45 + count / 100.0,
        )

        severity = severity_from_score(score)

        fp = fingerprint(
            "NETWORK_SCAN",
            evidence_id,
            source_ip,
            sorted(destinations),
        )

        detections.append(
            Detection(
                evidence_id=evidence_id,
                timestamp=first_seen.get(source_ip),
                detection_type="NETWORK_SCAN",
                severity=severity,
                title="Possible Network Discovery Scan",
                description=(
                    f"{source_ip} communicated with "
                    f"{count} unique destination IP addresses."
                ),
                source_ip=source_ip,
                protocol="IP",
                confidence=safe_confidence(score),
                status="new",
                fingerprint=fp,
                metadata_json={
                    "unique_destinations": count,
                    "destinations": sorted(destinations),
                },
            )
        )

    return detections


def detect_dns_anomalies(
    evidence_id: UUID,
    records: list[DNSRecord],
) -> list[Detection]:
    detections: list[Detection] = []

    for record in records:
        query = (
            record.query_name.strip(".")
            if record.query_name
            else ""
        )

        if len(query) >= 60:
            score = 0.78

            fp = fingerprint(
                "LONG_DNS_QUERY",
                evidence_id,
                record.id,
            )

            detections.append(
                Detection(
                    evidence_id=evidence_id,
                    timestamp=record.timestamp,
                    detection_type="DNS_ANOMALY",
                    severity="high",
                    title="Unusually Long DNS Query",
                    description=(
                        f"DNS query '{query}' is "
                        f"{len(query)} characters long."
                    ),
                    source_ip=record.source_ip,
                    destination_ip=record.destination_ip,
                    protocol="DNS",
                    confidence=score,
                    status="new",
                    fingerprint=fp,
                    metadata_json={
                        "query_name": query,
                        "length": len(query),
                        "query_type": record.query_type,
                    },
                )
            )

        if record.response_code == 3:
            fp = fingerprint(
                "DNS_NXDOMAIN",
                evidence_id,
                record.id,
            )

            detections.append(
                Detection(
                    evidence_id=evidence_id,
                    timestamp=record.timestamp,
                    detection_type="DNS_NXDOMAIN",
                    severity="low",
                    title="DNS NXDOMAIN Response",
                    description=(
                        f"DNS query '{query}' returned NXDOMAIN."
                    ),
                    source_ip=record.source_ip,
                    destination_ip=record.destination_ip,
                    protocol="DNS",
                    confidence=0.35,
                    status="new",
                    fingerprint=fp,
                    metadata_json={
                        "query_name": query,
                        "response_code": record.response_code,
                    },
                )
            )

    return detections


def detect_http_anomalies(
    evidence_id: UUID,
    records: list[HTTPTransaction],
) -> list[Detection]:
    detections: list[Detection] = []

    suspicious_fragments = (
        "/.env",
        "/wp-admin",
        "/wp-login",
        "/server-status",
        "/config.php",
        "/phpmyadmin",
        "/admin",
        "/etc/passwd",
    )

    for record in records:
        uri = record.uri or ""
        normalized = uri.lower()

        matched = next(
            (
                fragment
                for fragment in suspicious_fragments
                if fragment in normalized
            ),
            None,
        )

        if matched:
            fp = fingerprint(
                "HTTP_SUSPICIOUS_URI",
                evidence_id,
                record.id,
                matched,
            )

            detections.append(
                Detection(
                    evidence_id=evidence_id,
                    timestamp=record.timestamp,
                    detection_type="HTTP_ENUMERATION",
                    severity="medium",
                    title="Suspicious HTTP URI",
                    description=(
                        f"HTTP request accessed suspicious "
                        f"path pattern '{matched}'."
                    ),
                    source_ip=record.source_ip,
                    destination_ip=record.destination_ip,
                    destination_port=record.destination_port,
                    protocol="HTTP",
                    confidence=0.68,
                    status="new",
                    fingerprint=fp,
                    metadata_json={
                        "method": record.method,
                        "host": record.host,
                        "uri": uri,
                        "status_code": record.status_code,
                        "matched_pattern": matched,
                        "user_agent": record.user_agent,
                    },
                )
            )

        if (
            record.status_code is not None
            and record.status_code in {401, 403, 404}
        ):
            fp = fingerprint(
                "HTTP_ERROR",
                evidence_id,
                record.id,
            )

            detections.append(
                Detection(
                    evidence_id=evidence_id,
                    timestamp=record.timestamp,
                    detection_type="HTTP_ERROR",
                    severity="low",
                    title="HTTP Security-Relevant Response",
                    description=(
                        f"HTTP request returned status "
                        f"{record.status_code}."
                    ),
                    source_ip=record.source_ip,
                    destination_ip=record.destination_ip,
                    destination_port=record.destination_port,
                    protocol="HTTP",
                    confidence=0.30,
                    status="new",
                    fingerprint=fp,
                    metadata_json={
                        "status_code": record.status_code,
                        "method": record.method,
                        "host": record.host,
                        "uri": record.uri,
                    },
                )
            )

    return detections


def detect_beaconing(
    evidence_id: UUID,
    flows: list[NetworkFlow],
) -> list[Detection]:
    buckets: dict[tuple[str, str, int | None], list[float]] = defaultdict(list)

    for flow in flows:
        if (
            flow.source_ip
            and flow.destination_ip
            and flow.last_seen is not None
        ):
            buckets[
                (
                    flow.source_ip,
                    flow.destination_ip,
                    flow.destination_port,
                )
            ].append(flow.last_seen)

    detections: list[Detection] = []

    for (source, destination, port), timestamps in buckets.items():
        if len(timestamps) < 5:
            continue

        timestamps.sort()

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
            if timestamps[i] > timestamps[i - 1]
        ]

        if len(intervals) < 4:
            continue

        average = sum(intervals) / len(intervals)

        if average <= 0:
            continue

        variance = sum(
            (interval - average) ** 2
            for interval in intervals
        ) / len(intervals)

        standard_deviation = math.sqrt(variance)

        coefficient = (
            standard_deviation / average
            if average
            else 999
        )

        if coefficient > 0.20:
            continue

        score = min(
            0.90,
            0.55 + len(intervals) / 100.0,
        )

        fp = fingerprint(
            "BEACONING",
            evidence_id,
            source,
            destination,
            port,
        )

        detections.append(
            Detection(
                evidence_id=evidence_id,
                timestamp=timestamps[0],
                detection_type="BEACONING",
                severity="high",
                title="Possible Periodic Network Beacon",
                description=(
                    f"{source} communicated periodically with "
                    f"{destination}:{port}."
                ),
                source_ip=source,
                destination_ip=destination,
                destination_port=port,
                protocol="TCP",
                confidence=safe_confidence(score),
                status="new",
                fingerprint=fp,
                metadata_json={
                    "sample_count": len(timestamps),
                    "average_interval": average,
                    "standard_deviation": standard_deviation,
                    "coefficient_of_variation": coefficient,
                },
            )
        )

    return detections


def detect_high_volume(
    evidence_id: UUID,
    flows: list[NetworkFlow],
) -> list[Detection]:
    totals: dict[tuple[str, str], int] = defaultdict(int)

    for flow in flows:
        if flow.source_ip and flow.destination_ip:
            totals[
                (
                    flow.source_ip,
                    flow.destination_ip,
                )
            ] += flow.bytes or 0

    detections: list[Detection] = []

    for (source, destination), total_bytes in totals.items():
        if total_bytes < 50_000_000:
            continue

        score = min(
            1.0,
            0.55 + total_bytes / 500_000_000,
        )

        fp = fingerprint(
            "HIGH_VOLUME",
            evidence_id,
            source,
            destination,
        )

        detections.append(
            Detection(
                evidence_id=evidence_id,
                detection_type="HIGH_VOLUME_TRAFFIC",
                severity=severity_from_score(score),
                title="High-Volume Network Communication",
                description=(
                    f"{source} transferred approximately "
                    f"{total_bytes:,} bytes to {destination}."
                ),
                source_ip=source,
                destination_ip=destination,
                protocol="NETWORK",
                confidence=safe_confidence(score),
                status="new",
                fingerprint=fp,
                metadata_json={
                    "total_bytes": total_bytes,
                },
            )
        )

    return detections


def detect_rare_destinations(
    evidence_id: UUID,
    flows: list[NetworkFlow],
) -> list[Detection]:
    source_dest_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )

    for flow in flows:
        if flow.source_ip and flow.destination_ip:
            source_dest_counts[
                flow.source_ip
            ][
                flow.destination_ip
            ] += 1

    detections: list[Detection] = []

    for source, destinations in source_dest_counts.items():
        if len(destinations) < 3:
            continue

        total = sum(destinations.values())

        for destination, count in destinations.items():
            ratio = count / total if total else 0

            if count <= 2 and ratio < 0.01:
                fp = fingerprint(
                    "RARE_DESTINATION",
                    evidence_id,
                    source,
                    destination,
                )

                detections.append(
                    Detection(
                        evidence_id=evidence_id,
                        detection_type="RARE_DESTINATION",
                        severity="low",
                        title="Rare Network Destination",
                        description=(
                            f"{source} communicated infrequently "
                            f"with destination {destination}."
                        ),
                        source_ip=source,
                        destination_ip=destination,
                        protocol="NETWORK",
                        confidence=0.35,
                        status="new",
                        fingerprint=fp,
                        metadata_json={
                            "connection_count": count,
                            "source_total_connections": total,
                        },
                    )
                )

    return detections