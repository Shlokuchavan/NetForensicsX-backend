import hashlib
import uuid
from pathlib import Path

from fastapi import UploadFile

UPLOAD_DIR = Path("/evidence/uploads")

ALLOWED_EXTENSIONS = {
    ".pcap",
    ".pcapng",
    ".cap",
}


def validate_evidence_file(filename: str) -> None:
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Unsupported evidence type. "
            "Only PCAP, PCAPNG and CAP files are allowed."
        )


async def save_evidence_file(
    upload: UploadFile,
) -> tuple[str, str, int]:
    if not upload.filename:
        raise ValueError("Filename is missing")

    validate_evidence_file(upload.filename)

    UPLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    extension = Path(upload.filename).suffix.lower()

    stored_filename = (
        f"{uuid.uuid4().hex}{extension}"
    )

    destination = UPLOAD_DIR / stored_filename

    sha256 = hashlib.sha256()
    file_size = 0

    with destination.open("wb") as output:
        while chunk := await upload.read(1024 * 1024):
            output.write(chunk)

            sha256.update(chunk)

            file_size += len(chunk)

    await upload.close()

    return (
        stored_filename,
        sha256.hexdigest(),
        file_size,
    )