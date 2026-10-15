import os

from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import (
    TLSClientHello,
    TLSServerHello,
)
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence
from app.models.tls_session import TLSSession


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


def safe_string(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(
            errors="replace"
        )

    return str(value)


def extract_tls_version(tls_layer):
    for attribute in (
        "version",
        "version_str",
    ):
        value = getattr(
            tls_layer,
            attribute,
            None,
        )

        if value is not None:
            return safe_string(value)

    return None


def extract_cipher(tls_layer):
    for attribute in (
        "cipher",
        "cipher_suite",
        "cipher_suite_id",
    ):
        value = getattr(
            tls_layer,
            attribute,
            None,
        )

        if value is not None:
            return safe_string(value)

    return None


def extract_sni(client_hello):
    extensions = getattr(
        client_hello,
        "ext",
        None,
    )

    if not extensions:
        return None

    for extension in extensions:

        extension_name = extension.__class__.__name__

        if "ServerName" not in extension_name:
            continue

        servernames = getattr(
            extension,
            "servernames",
            None,
        )

        if not servernames:
            continue

        for server_name in servernames:

            value = getattr(
                server_name,
                "servername",
                None,
            )

            if value is not None:
                return safe_string(value)

    return None


def parse_tls_packet(packet):
    if TLS not in packet:
        return None

    source_ip, destination_ip = get_ip_addresses(packet)

    if not source_ip or not destination_ip:
        return None

    source_port, destination_port = get_tcp_ports(packet)

    if source_port is None or destination_port is None:
        return None

    tls_layer = packet[TLS]

    timestamp = float(packet.time)

    if TLSClientHello in packet:

        client_hello = packet[TLSClientHello]

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "tls_version": extract_tls_version(
                client_hello
            ),
            "sni": extract_sni(
                client_hello
            ),
            "cipher": extract_cipher(
                client_hello
            ),
            "handshake_type": "ClientHello",
        }

    if TLSServerHello in packet:

        server_hello = packet[TLSServerHello]

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "tls_version": extract_tls_version(
                server_hello
            ),
            "sni": None,
            "cipher": extract_cipher(
                server_hello
            ),
            "handshake_type": "ServerHello",
        }

    return None


async def analyze_tls(
    db: AsyncSession,
    evidence_id,
) -> list[TLSSession]:

    evidence = await db.get(
        Evidence,
        evidence_id,
    )

    if evidence is None:
        raise ValueError(
            "Evidence not found"
        )

    if not os.path.exists(
        evidence.file_path
    ):
        raise ValueError(
            f"Evidence file not found: {evidence.file_path}"
        )

    await db.execute(
        delete(TLSSession).where(
            TLSSession.evidence_id
            == evidence_id
        )
    )

    records = []

    with PcapReader(
        evidence.file_path
    ) as reader:

        for packet in reader:

            if TLS not in packet:
                continue

            parsed = parse_tls_packet(
                packet
            )

            if not parsed:
                continue

            session = TLSSession(
                evidence_id=evidence_id,
                timestamp=parsed["timestamp"],
                source_ip=parsed["source_ip"],
                destination_ip=parsed["destination_ip"],
                source_port=parsed["source_port"],
                destination_port=parsed["destination_port"],
                tls_version=parsed["tls_version"],
                sni=parsed["sni"],
                cipher=parsed["cipher"],
                handshake_type=parsed["handshake_type"],
            )

            db.add(session)
            records.append(session)

    await db.commit()

    for record in records:
        await db.refresh(record)

    return records