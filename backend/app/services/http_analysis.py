import os
import re

from scapy.all import IP, IPv6, Raw, TCP, PcapReader
from scapy.layers.http import HTTPRequest, HTTPResponse
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence
from app.models.http_transaction import HTTPTransaction


HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
}


def get_ip_addresses(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


def get_tcp_ports(packet):
    if TCP not in packet:
        return None, None

    return packet[TCP].sport, packet[TCP].dport


def decode_value(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(errors="replace")

    return str(value)


def clean_header(value):
    if value is None:
        return None

    value = decode_value(value)

    return value.strip()


def parse_http_request(packet):
    if HTTPRequest not in packet:
        return None

    source_ip, destination_ip = get_ip_addresses(packet)

    if not source_ip or not destination_ip:
        return None

    source_port, destination_port = get_tcp_ports(packet)

    request = packet[HTTPRequest]

    method = clean_header(
        getattr(request, "Method", None)
    )

    host = clean_header(
        getattr(request, "Host", None)
    )

    path = clean_header(
        getattr(request, "Path", None)
    )

    user_agent = clean_header(
        getattr(request, "User_Agent", None)
    )

    return {
        "timestamp": float(packet.time),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "method": method,
        "host": host,
        "uri": path,
        "status_code": None,
        "user_agent": user_agent,
    }


def parse_http_response(packet):
    if HTTPResponse not in packet:
        return None

    source_ip, destination_ip = get_ip_addresses(packet)

    if not source_ip or not destination_ip:
        return None

    source_port, destination_port = get_tcp_ports(packet)

    response = packet[HTTPResponse]

    status_code = getattr(
        response,
        "Status_Code",
        None,
    )

    try:
        if status_code is not None:
            status_code = int(
                decode_value(status_code)
            )
    except (ValueError, TypeError):
        status_code = None

    return {
        "timestamp": float(packet.time),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "method": None,
        "host": None,
        "uri": None,
        "status_code": status_code,
        "user_agent": None,
    }


def parse_raw_http(packet):
    if Raw not in packet:
        return None

    source_ip, destination_ip = get_ip_addresses(packet)

    if not source_ip or not destination_ip:
        return None

    source_port, destination_port = get_tcp_ports(packet)

    if source_port is None or destination_port is None:
        return None

    raw = bytes(packet[Raw].load)

    if not raw:
        return None

    try:
        text = raw.decode(
            "utf-8",
            errors="replace",
        )
    except Exception:
        return None

    lines = text.splitlines()

    if not lines:
        return None

    first_line = lines[0].strip()

    request_match = re.match(
        r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/\d\.\d$",
        first_line,
    )

    if request_match:
        method = request_match.group(1)
        uri = request_match.group(2)

        host = None
        user_agent = None

        for line in lines[1:]:
            if ":" not in line:
                continue

            key, value = line.split(
                ":",
                1,
            )

            key = key.strip().lower()
            value = value.strip()

            if key == "host":
                host = value

            elif key == "user-agent":
                user_agent = value

        return {
            "timestamp": float(packet.time),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "method": method,
            "host": host,
            "uri": uri,
            "status_code": None,
            "user_agent": user_agent,
        }

    response_match = re.match(
        r"^HTTP/\d\.\d\s+(\d{3})",
        first_line,
    )

    if response_match:
        return {
            "timestamp": float(packet.time),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "method": None,
            "host": None,
            "uri": None,
            "status_code": int(
                response_match.group(1)
            ),
            "user_agent": None,
        }

    return None


async def analyze_http(
    db: AsyncSession,
    evidence_id,
) -> list[HTTPTransaction]:

    evidence = await db.get(
        Evidence,
        evidence_id,
    )

    if evidence is None:
        raise ValueError("Evidence not found")

    if not os.path.exists(evidence.file_path):
        raise ValueError(
            f"Evidence file not found: {evidence.file_path}"
        )

    await db.execute(
        delete(HTTPTransaction).where(
            HTTPTransaction.evidence_id == evidence_id
        )
    )

    records = []

    with PcapReader(
        evidence.file_path
    ) as reader:

        for packet in reader:

            parsed = None

            if HTTPRequest in packet:
                parsed = parse_http_request(packet)

            elif HTTPResponse in packet:
                parsed = parse_http_response(packet)

            elif Raw in packet and TCP in packet:
                parsed = parse_raw_http(packet)

            if not parsed:
                continue

            transaction = HTTPTransaction(
                evidence_id=evidence_id,
                timestamp=parsed["timestamp"],
                source_ip=parsed["source_ip"],
                destination_ip=parsed["destination_ip"],
                source_port=parsed["source_port"],
                destination_port=parsed["destination_port"],
                method=parsed["method"],
                host=parsed["host"],
                uri=parsed["uri"],
                status_code=parsed["status_code"],
                user_agent=parsed["user_agent"],
            )

            db.add(transaction)
            records.append(transaction)

    await db.commit()

    for record in records:
        await db.refresh(record)

    return records