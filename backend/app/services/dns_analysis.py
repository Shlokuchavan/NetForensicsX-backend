import os

from scapy.all import IP, IPv6, PcapReader
from scapy.layers.dns import DNS, DNSQR, DNSRR
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns_record import DNSRecord
from app.models.evidence import Evidence


DNS_TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    255: "ANY",
}


def decode_dns_name(value) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode(errors="replace").rstrip(".")

    return str(value).rstrip(".")


def get_ip_addresses(packet):
    source_ip = None
    destination_ip = None

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    return source_ip, destination_ip


def parse_dns_packet(packet):
    if DNS not in packet:
        return []

    source_ip, destination_ip = get_ip_addresses(packet)

    if not source_ip or not destination_ip:
        return []

    dns = packet[DNS]

    records = []

    query_count = int(dns.qdcount or 0)

    if DNSQR in dns:

        question = dns.qd

        for _ in range(query_count):
            if question is None:
                break

            query_name = decode_dns_name(question.qname)

            query_type = DNS_TYPE_MAP.get(
                int(question.qtype),
                str(question.qtype),
            )

            records.append(
                {
                    "timestamp": float(packet.time),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "query_name": query_name,
                    "query_type": query_type,
                    "response_code": int(dns.rcode),
                    "answers": None,
                }
            )

            question = getattr(
                question,
                "payload",
                None,
            )

    return records


async def analyze_dns(
    db: AsyncSession,
    evidence_id,
) -> list[DNSRecord]:

    evidence = await db.get(Evidence, evidence_id)

    if evidence is None:
        raise ValueError("Evidence not found")

    if not os.path.exists(evidence.file_path):
        raise ValueError(
            f"Evidence file not found: {evidence.file_path}"
        )

    await db.execute(
        delete(DNSRecord).where(
            DNSRecord.evidence_id == evidence_id
        )
    )

    records = []

    with PcapReader(evidence.file_path) as reader:

        for packet in reader:

            if DNS not in packet:
                continue

            parsed_records = parse_dns_packet(packet)

            for record_data in parsed_records:

                record = DNSRecord(
                    evidence_id=evidence_id,
                    timestamp=record_data["timestamp"],
                    source_ip=record_data["source_ip"],
                    destination_ip=record_data["destination_ip"],
                    query_name=record_data["query_name"],
                    query_type=record_data["query_type"],
                    response_code=record_data["response_code"],
                    answers=record_data["answers"],
                )

                db.add(record)
                records.append(record)

    await db.commit()

    for record in records:
        await db.refresh(record)

    return records