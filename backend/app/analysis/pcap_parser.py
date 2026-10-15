from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import (
    PcapReader,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
)


def parse_pcap(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {file_path}"
        )

    packet_count = 0
    hosts = set()
    protocols = Counter()

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    dns_count = 0
    http_count = 0
    https_count = 0

    capture_start = None
    capture_end = None

    flows = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "first_seen": None,
            "last_seen": None,
        }
    )

    with PcapReader(str(path)) as reader:
        for packet in reader:
            packet_count += 1

            timestamp = float(packet.time)

            if capture_start is None:
                capture_start = timestamp

            capture_end = timestamp

            source_ip = None
            destination_ip = None

            # -------------------------------------------------
            # IP layer
            # -------------------------------------------------

            if IP in packet:
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst

            elif IPv6 in packet:
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst

            if source_ip:
                hosts.add(source_ip)

            if destination_ip:
                hosts.add(destination_ip)

            # -------------------------------------------------
            # Transport layer
            # -------------------------------------------------

            protocol = "OTHER"

            source_port = None
            destination_port = None

            if TCP in packet:
                protocol = "TCP"

                tcp_count += 1

                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)

            elif UDP in packet:
                protocol = "UDP"

                udp_count += 1

                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)

            elif ICMP in packet:
                protocol = "ICMP"

                icmp_count += 1

            protocols[protocol] += 1

            # -------------------------------------------------
            # Protocol heuristics
            # -------------------------------------------------

            if (
                source_port == 53
                or destination_port == 53
            ):
                dns_count += 1

            if (
                source_port == 80
                or destination_port == 80
            ):
                http_count += 1

            if (
                source_port == 443
                or destination_port == 443
            ):
                https_count += 1

            # -------------------------------------------------
            # Flow extraction
            # -------------------------------------------------

            if source_ip and destination_ip:

                flow_key = (
                    source_ip,
                    destination_ip,
                    protocol,
                    source_port,
                    destination_port,
                )

                flow = flows[flow_key]

                flow["packets"] += 1
                flow["bytes"] += len(packet)

                if flow["first_seen"] is None:
                    flow["first_seen"] = timestamp

                flow["last_seen"] = timestamp

    # ---------------------------------------------------------
    # Convert flow dictionary to serializable list
    # ---------------------------------------------------------

    flow_records = []

    for (
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
    ), flow in flows.items():

        flow_records.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "packets": flow["packets"],
                "bytes": flow["bytes"],
                "first_seen": flow["first_seen"],
                "last_seen": flow["last_seen"],
            }
        )

    duration = 0

    if (
        capture_start is not None
        and capture_end is not None
    ):
        duration = capture_end - capture_start

    return {
        "file": path.name,

        "packet_count": packet_count,

        "host_count": len(hosts),

        "hosts": sorted(hosts),

        "protocols": dict(protocols),

        "tcp_count": tcp_count,

        "udp_count": udp_count,

        "icmp_count": icmp_count,

        "dns_count": dns_count,

        "http_count": http_count,

        "https_count": https_count,

        "capture_start": capture_start,

        "capture_end": capture_end,

        "duration": duration,

        "flow_count": len(flow_records),

        "flows": flow_records,
    }