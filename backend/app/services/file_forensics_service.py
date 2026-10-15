
from __future__ import annotations

import asyncio
import hashlib
import re
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence
from app.models.http_transaction import HTTPTransaction


MAX_PCAP_BYTES = 250 * 1024 * 1024
MAX_PACKETS = 500_000
MAX_EXTRACTED_FILE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_FILES = 200

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".hta", ".msi",
    ".jar", ".sh", ".elf", ".apk",
}

EXECUTABLE_SIGNATURES = {
    "PE executable": (b"MZ",),
    "ELF executable": (b"\x7fELF",),
    "Mach-O executable": (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ),
}

MIME_SIGNATURES = (
    (b"MZ", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "application/x-elf"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def _safe_filename(value: str | None) -> str:
    name = unquote((value or "").replace("\\", "/").split("/")[-1])
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).strip(" .")
    if not name or name in {".", ".."}:
        name = "recovered_artifact.bin"
    return name[:180]


def _filename_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        name = Path(urlparse(url).path).name
        return _safe_filename(name) if name else None
    except (ValueError, TypeError):
        return None


def _content_disposition_filename(headers: bytes) -> str | None:
    match = re.search(
        rb'(?im)^content-disposition\s*:\s*([^\r\n]+)',
        headers,
    )
    if not match:
        return None

    value = match.group(1).decode("latin-1", errors="replace")
    match = re.search(
        r"""filename\*?=(?:UTF-8''|")?([^";]+)""",
        value,
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    return _safe_filename(match.group(1).strip().strip('"'))


def _content_type(headers: bytes) -> str | None:
    match = re.search(
        rb"(?im)^content-type\s*:\s*([^\r\n;]+)",
        headers,
    )
    if not match:
        return None
    return match.group(1).decode("latin-1", errors="replace").strip().lower()


def _declared_length(headers: bytes) -> int | None:
    match = re.search(
        rb"(?im)^content-length\s*:\s*(\d+)",
        headers,
    )
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _chunked_decode(data: bytes) -> bytes | None:
    """Decode a complete HTTP chunked body; return None if incomplete/invalid."""
    output = bytearray()
    cursor = 0

    try:
        while True:
            line_end = data.find(b"\r\n", cursor)
            if line_end < 0:
                return None

            size_text = data[cursor:line_end].split(b";", 1)[0].strip()
            size = int(size_text, 16)
            cursor = line_end + 2

            if size == 0:
                return bytes(output)

            end = cursor + size
            if end + 2 > len(data) or data[end:end + 2] != b"\r\n":
                return None

            output.extend(data[cursor:end])
            cursor = end + 2

            if len(output) > MAX_EXTRACTED_FILE_BYTES:
                return None
    except (ValueError, OverflowError):
        return None

def _parse_http_requests(stream: bytes) -> list[dict[str, Any]]:
    """Extract HTTP request metadata, including the original download filename."""
    requests: list[dict[str, Any]] = []
    cursor = 0

    request_pattern = re.compile(
        rb"(?m)(?:^|\r\n)"
        rb"(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?\r\n"
    )

    while len(requests) < MAX_EXTRACTED_FILES:
        match = request_pattern.search(stream, cursor)
        if not match:
            break

        header_start = match.end()
        header_end = stream.find(b"\r\n\r\n", header_start)
        if header_end < 0:
            break

        headers = stream[header_start:header_end]
        target = match.group(2).decode("latin-1", errors="replace")

        host_match = re.search(
            rb"(?im)^host\s*:\s*([^\r\n]+)", headers
        )
        host = (
            host_match.group(1).decode("latin-1", errors="replace").strip()
            if host_match else None
        )

        path = urlparse(target).path if target.startswith(("http://", "https://")) else target.split("?", 1)[0]
        filename = _filename_from_url(path)

        requests.append({
            "method": match.group(1).decode("ascii"),
            "target": target,
            "host": host,
            "filename": filename,
        })

        cursor = header_end + 4

    return requests

def _parse_http_responses(stream: bytes) -> list[dict[str, Any]]:
    """
    Extract complete HTTP response bodies from one reconstructed TCP direction.
    This deliberately does not claim to decrypt TLS or recover incomplete streams.
    """
    responses: list[dict[str, Any]] = []
    cursor = 0

    while len(responses) < MAX_EXTRACTED_FILES:
        start = stream.find(b"HTTP/", cursor)
        if start < 0:
            break

        header_end = stream.find(b"\r\n\r\n", start)
        if header_end < 0:
            break

        header_block = stream[start:header_end]
        first_line = header_block.split(b"\r\n", 1)[0]
        status_match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
        if not status_match:
            cursor = start + 5
            continue

        status = int(status_match.group(1))
        body_start = header_end + 4
        headers_lower = header_block.lower()

        if status in {204, 304} or 100 <= status < 200:
            cursor = body_start
            continue

        if b"transfer-encoding:" in headers_lower and b"chunked" in headers_lower:
            decoded = _chunked_decode(stream[body_start:])
            if decoded is None:
                break
            body = decoded
            # Locate the end of the encoded chunked body to continue parsing.
            scan = body_start
            consumed = 0
            while True:
                line_end = stream.find(b"\r\n", scan)
                if line_end < 0:
                    break
                try:
                    size = int(
                        stream[scan:line_end].split(b";", 1)[0].strip(),
                        16,
                    )
                except ValueError:
                    break
                scan = line_end + 2
                if size == 0:
                    terminal = stream.find(b"\r\n", scan)
                    cursor = terminal + 2 if terminal >= 0 else len(stream)
                    break
                scan += size + 2
                consumed = scan - body_start
                if consumed > MAX_EXTRACTED_FILE_BYTES * 2:
                    break
        else:
            length = _declared_length(header_block)
            if length is None:
                # Without a length, the end of this response is ambiguous.
                break
            if length < 0 or length > MAX_EXTRACTED_FILE_BYTES:
                cursor = body_start + min(length, len(stream))
                continue
            body_end = body_start + length
            if body_end > len(stream):
                break
            body = stream[body_start:body_end]
            cursor = body_end

        disposition_name = _content_disposition_filename(header_block)
        mime = _content_type(header_block)

        if body and (
            disposition_name
            or b"attachment" in headers_lower
            or mime in {
                "application/octet-stream",
                "application/zip",
                "application/pdf",
                "application/x-dosexec",
                "application/vnd.microsoft.portable-executable",
                "application/x-elf",
            }
            or body.startswith((b"MZ", b"\x7fELF", b"%PDF-", b"PK\x03\x04"))
        ):
            responses.append({
                "filename": disposition_name,
                "content_type": mime,
                "status_code": status,
                "body": body,
            })

        if cursor <= start:
            cursor = body_start

    return responses


def _resolve_evidence_path(evidence: Evidence) -> Path | None:
    """
    Resolve the existing evidence path against common container/project roots.
    Only known evidence path/name values are considered.
    """
    raw_path = getattr(evidence, "file_path", None)
    stored_filename = getattr(evidence, "stored_filename", None)

    candidates: list[Path] = []

    if raw_path:
        raw = Path(str(raw_path))
        if raw.is_absolute():
            candidates.append(raw)
        else:
            candidates.extend([
                Path.cwd() / raw,
                Path.cwd() / "backend" / raw,
                Path.cwd() / "evidence" / raw.name,
                Path.cwd() / "evidence" / "uploads" / raw.name,
            ])

    if stored_filename:
        name = Path(str(stored_filename)).name
        candidates.extend([
            Path.cwd() / "evidence" / "uploads" / name,
            Path.cwd() / "backend" / "evidence" / "uploads" / name,
            Path.cwd() / "app" / "evidence" / "uploads" / name,
            Path("/app/evidence/uploads") / name,
        ])

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved.is_file() and resolved.stat().st_size <= MAX_PCAP_BYTES:
                return resolved
        except (OSError, RuntimeError):
            continue

    return None


def _recover_http_files(pcap_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []

    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader
    except ImportError:
        return [], [
            "Scapy is not installed; PCAP body recovery was skipped. "
            "Install scapy in the backend environment to enable recovery."
        ]

    if pcap_path.stat().st_size > MAX_PCAP_BYTES:
        return [], ["PCAP exceeds the configured processing size limit."]

    streams: dict[tuple[str, int, str, int], list[tuple[float, bytes]]] = defaultdict(list)
    packet_count = 0
    total_payload = 0

    try:
        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                packet_count += 1
                if packet_count > MAX_PACKETS:
                    warnings.append("Packet processing limit reached.")
                    break

                if TCP not in packet:
                    continue

                tcp = packet[TCP]
                payload = bytes(tcp.payload)
                if not payload:
                    continue

                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                elif IPv6 in packet:
                    src = packet[IPv6].src
                    dst = packet[IPv6].dst
                else:
                    continue

                total_payload += len(payload)
                if total_payload > MAX_PCAP_BYTES:
                    warnings.append("TCP payload processing limit reached.")
                    break

                key = (src, int(tcp.sport), dst, int(tcp.dport))
                timestamp = float(getattr(packet, "time", 0.0))
                streams[key].append((timestamp, payload))

    except Exception as exc:
        warnings.append(f"PCAP parsing failed: {type(exc).__name__}.")
        return [], warnings

    
    recovered: list[dict[str, Any]] = []
    processed_responses: set[tuple[str, int, str, int]] = set()

    for key, segments in streams.items():
        segments.sort(key=lambda item: item[0])
        stream = b"".join(data for _, data in segments)

        # This direction is treated as a potential HTTP response stream.
        responses = _parse_http_responses(stream)
        if not responses:
            continue

        # Requests usually travel in the reverse direction.
        reverse_key = (key[2], key[3], key[0], key[1])
        request_segments = streams.get(reverse_key, [])
        request_segments.sort(key=lambda item: item[0])
        request_stream = b"".join(data for _, data in request_segments)
        requests = _parse_http_requests(request_stream)

        for response_index, response in enumerate(responses):
            body = response["body"]
            if not body or len(body) > MAX_EXTRACTED_FILE_BYTES:
                continue

            # Skip a response stream already processed.
            if key in processed_responses:
                continue

            request = (
                requests[response_index]
                if response_index < len(requests)
                else {}
            )

            original_name = (
                response.get("filename")
                or request.get("filename")
                or f"recovered_{len(recovered) + 1}.bin"
            )

            target = request.get("target")
            host = request.get("host")

            if target and target.startswith(("http://", "https://")):
                original_url = target
            elif host and target:
                original_url = f"http://{host}{target}"
            else:
                original_url = None

            mime = (response.get("content_type") or "").lower()
            is_file = bool(
                response.get("filename")
                or request.get("filename")
                or body.startswith((
                    b"MZ", b"\x7fELF", b"%PDF-", b"PK\x03\x04"
                ))
                or mime in {
                    "application/octet-stream",
                    "application/zip",
                    "application/pdf",
                    "application/x-dosexec",
                    "application/vnd.microsoft.portable-executable",
                    "application/x-elf",
                }
            )

            if not is_file:
                continue

            recovered.append({
                **response,
                "filename": _safe_filename(original_name),
                "url": original_url,
                "host": host,
                "source_ip": key[0],
                "source_port": key[1],
                "destination_ip": key[2],
                "destination_port": key[3],
                "first_packet_timestamp": (
                    segments[0][0] if segments else None
                ),
            })

            processed_responses.add(key)

            if len(recovered) >= MAX_EXTRACTED_FILES:
                warnings.append("Recovered-file count limit reached.")
                return recovered, warnings

    if not recovered:
        warnings.append(
            "No complete, recognizable HTTP file responses were recovered. "
            "HTTPS/TLS payloads, incomplete TCP streams, and unsupported "
            "transfer encodings may prevent recovery."
        )

    return recovered, warnings



def _identify_file(data: bytes, filename: str | None, mime: str | None) -> dict[str, Any]:
    actual_type = "unknown"
    for signature, detected_mime in MIME_SIGNATURES:
        if data.startswith(signature):
            actual_type = detected_mime
            break

    if actual_type == "unknown":
        for description, signatures in EXECUTABLE_SIGNATURES.items():
            if any(data.startswith(sig) for sig in signatures):
                actual_type = description
                break

    extension = Path(filename or "").suffix.lower()
    suspicious_reasons: list[str] = []

    if extension in SUSPICIOUS_EXTENSIONS:
        suspicious_reasons.append(f"Executable or script extension: {extension}")

    if actual_type in {"PE executable", "ELF executable", "Mach-O executable"}:
        suspicious_reasons.append(f"Executable signature detected: {actual_type}")

    if extension in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"} and (
        actual_type in {"PE executable", "ELF executable", "Mach-O executable"}
        or actual_type == "application/vnd.microsoft.portable-executable"
    ):
        suspicious_reasons.append("File extension does not match executable content")

    if mime and actual_type != "unknown":
        expected = mime.lower().split(";", 1)[0].strip()
        if expected not in {"application/octet-stream", actual_type}:
            if not (expected == "application/x-dosexec" and actual_type.startswith("application/vnd.microsoft")):
                suspicious_reasons.append(
                    f"HTTP MIME type ({expected}) differs from detected signature ({actual_type})"
                )

    digest = hashlib.sha256(data).hexdigest()

    return {
        "sha256": digest,
        "size_bytes": len(data),
        "file_extension": extension or None,
        "declared_mime_type": mime,
        "detected_file_type": actual_type,
        "suspicious": bool(suspicious_reasons),
        "suspicious_reasons": suspicious_reasons,
    }


async def analyze_file_forensics(
    db: AsyncSession,
    case_id: UUID,
    evidence_id: UUID,
) -> dict[str, Any]:
    evidence = await db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise ValueError("Evidence not found in this case")

    result = await db.execute(
        select(HTTPTransaction)
        .where(HTTPTransaction.evidence_id == evidence_id)
        .order_by(HTTPTransaction.timestamp.asc().nullslast())
        .limit(5000)
    )
    transactions = list(result.scalars().all())

    pcap_path = _resolve_evidence_path(evidence)
    recovered: list[dict[str, Any]] = []
    warnings: list[str] = []

    if pcap_path is not None:
        recovered, warnings = await asyncio.to_thread(
            _recover_http_files, pcap_path
        )
    else:
        warnings.append(
            "Original PCAP file could not be located from Evidence.file_path "
            "or Evidence.stored_filename. Metadata analysis is still available."
        )

    artifacts: list[dict[str, Any]] = []
    extracted_dir: Path | None = None

    if recovered and pcap_path is not None:
        extracted_dir = pcap_path.parent / "extracted" / str(evidence_id)
        try:
            extracted_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            extracted_dir = None
            warnings.append("Could not create the extracted-evidence directory.")

    for index, item in enumerate(recovered, start=1):
        body = item.pop("body")
        name = _safe_filename(item.get("filename") or f"recovered_{index}.bin")
        metadata = _identify_file(body, name, item.get("content_type"))
        saved_path: str | None = None

        if extracted_dir is not None:
            target = extracted_dir / f"{index:03d}_{metadata['sha256'][:12]}_{name}"
            try:
                target.write_bytes(body)
                saved_path = str(target)
            except OSError:
                warnings.append(f"Failed to save recovered artifact {name}.")

        artifacts.append({
            "artifact_id": f"recovered-{index}",
            "filename": name,
            "source": "pcap_http_response",
            "recovered": True,
            "saved_path": saved_path,
            "url": None,
            "host": None,
            "http_status": item.get("status_code"),
            "timestamp": item.get("first_packet_timestamp"),
            "source_ip": item.get("source_ip"),
            "destination_ip": item.get("destination_ip"),
            **metadata,
        })

    # Metadata-only records are useful leads, but are not represented as recovered files.
    for tx in transactions:
        uri = getattr(tx, "uri", None)
        host = getattr(tx, "host", None)
        url = f"http://{host}{uri or '/'}" if host else uri
        filename = _filename_from_url(uri)

        if not filename and not (getattr(tx, "method", None) or "").upper() == "GET":
            continue

        artifacts.append({
            "artifact_id": f"http-{getattr(tx, 'id', '')}",
            "filename": filename,
            "source": "http_transaction_metadata",
            "recovered": False,
            "saved_path": None,
            "url": url,
            "host": host,
            "http_status": getattr(tx, "status_code", None),
            "timestamp": getattr(tx, "timestamp", None),
            "source_ip": getattr(tx, "source_ip", None),
            "destination_ip": getattr(tx, "destination_ip", None),
            "source_port": getattr(tx, "source_port", None),
            "destination_port": getattr(tx, "destination_port", None),
            "method": getattr(tx, "method", None),
            "user_agent": getattr(tx, "user_agent", None),
            "sha256": None,
            "size_bytes": None,
            "file_extension": Path(filename).suffix.lower() if filename else None,
            "declared_mime_type": None,
            "detected_file_type": "not_recovered",
            "suspicious": bool(
                filename and Path(filename).suffix.lower() in SUSPICIOUS_EXTENSIONS
            ),
            "suspicious_reasons": (
                [f"Suspicious download filename extension: {Path(filename).suffix.lower()}"]
                if filename and Path(filename).suffix.lower() in SUSPICIOUS_EXTENSIONS
                else []
            ),
        })

    return {
        "case_id": str(case_id),
        "evidence_id": str(evidence_id),
        "evidence_filename": getattr(evidence, "original_filename", None),
        "pcap_found": pcap_path is not None,
        "transactions_examined": len(transactions),
        "recovered_files": sum(1 for item in artifacts if item["recovered"]),
        "metadata_artifacts": sum(1 for item in artifacts if not item["recovered"]),
        "suspicious_artifacts": sum(1 for item in artifacts if item["suspicious"]),
        "artifacts": artifacts,
        "warnings": warnings,
        "limitations": [
            "A filename or URL is not proof that file bytes were recovered.",
            "A recovered executable is not proof that it was executed.",
            "TLS-encrypted HTTPS content is not decrypted by this service.",
            "TCP retransmission and complex stream reassembly can affect recovery.",
        ],
    }