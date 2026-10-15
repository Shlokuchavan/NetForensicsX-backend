from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.pcap_parser import parse_pcap
from app.models.evidence import Evidence
from app.models.network_flow import NetworkFlow
from app.models.pcap_analysis import PcapAnalysis


async def analyze_evidence(
    db: AsyncSession,
    evidence_id: UUID,
) -> PcapAnalysis:

    # ---------------------------------------------------------
    # Get evidence
    # ---------------------------------------------------------

    result = await db.execute(
        select(Evidence).where(
            Evidence.id == evidence_id
        )
    )

    evidence = result.scalar_one_or_none()

    if evidence is None:
        raise ValueError("Evidence not found")

    # ---------------------------------------------------------
    # Parse PCAP
    # ---------------------------------------------------------

    parsed = parse_pcap(
        evidence.file_path
    )

    # ---------------------------------------------------------
    # Get existing analysis
    # ---------------------------------------------------------

    existing_result = await db.execute(
        select(PcapAnalysis).where(
            PcapAnalysis.evidence_id == evidence_id
        )
    )

    existing = (
        existing_result.scalar_one_or_none()
    )

    # ---------------------------------------------------------
    # Create or update analysis
    # ---------------------------------------------------------

    if existing:

        analysis = existing

        analysis.packet_count = (
            parsed["packet_count"]
        )

        analysis.host_count = (
            parsed["host_count"]
        )

        analysis.tcp_count = (
            parsed["tcp_count"]
        )

        analysis.udp_count = (
            parsed["udp_count"]
        )

        analysis.icmp_count = (
            parsed["icmp_count"]
        )

        analysis.dns_count = (
            parsed["dns_count"]
        )

        analysis.http_count = (
            parsed["http_count"]
        )

        analysis.https_count = (
            parsed["https_count"]
        )

        analysis.flow_count = (
            parsed["flow_count"]
        )

        analysis.capture_start = (
            parsed["capture_start"]
        )

        analysis.capture_end = (
            parsed["capture_end"]
        )

        analysis.duration = (
            parsed["duration"]
        )

        analysis.status = "completed"

    else:

        analysis = PcapAnalysis(
            evidence_id=evidence.id,

            packet_count=parsed[
                "packet_count"
            ],

            host_count=parsed[
                "host_count"
            ],

            tcp_count=parsed[
                "tcp_count"
            ],

            udp_count=parsed[
                "udp_count"
            ],

            icmp_count=parsed[
                "icmp_count"
            ],

            dns_count=parsed[
                "dns_count"
            ],

            http_count=parsed[
                "http_count"
            ],

            https_count=parsed[
                "https_count"
            ],

            flow_count=parsed[
                "flow_count"
            ],

            capture_start=parsed[
                "capture_start"
            ],

            capture_end=parsed[
                "capture_end"
            ],

            duration=parsed[
                "duration"
            ],

            status="completed",
        )

        db.add(analysis)

    # ---------------------------------------------------------
    # Replace existing flows
    # ---------------------------------------------------------
    #
    # Re-analysis should not create duplicates.
    #
    # ---------------------------------------------------------

    await db.execute(
        delete(NetworkFlow).where(
            NetworkFlow.evidence_id
            == evidence_id
        )
    )

    # ---------------------------------------------------------
    # Insert extracted flows
    # ---------------------------------------------------------

    for flow in parsed["flows"]:

        db.add(
            NetworkFlow(
                evidence_id=evidence_id,

                source_ip=flow[
                    "source_ip"
                ],

                destination_ip=flow[
                    "destination_ip"
                ],

                protocol=flow[
                    "protocol"
                ],

                source_port=flow[
                    "source_port"
                ],

                destination_port=flow[
                    "destination_port"
                ],

                packets=flow[
                    "packets"
                ],

                bytes=flow[
                    "bytes"
                ],

                first_seen=flow[
                    "first_seen"
                ],

                last_seen=flow[
                    "last_seen"
                ],
            )
        )

    # ---------------------------------------------------------
    # Commit everything
    # ---------------------------------------------------------

    await db.commit()

    await db.refresh(analysis)

    return analysis