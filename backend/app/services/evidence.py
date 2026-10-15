
import hashlib
import os
import uuid
from pathlib import Path

from fastapi import UploadFile


# Resolve the backend directory automatically.
# This avoids trying to write to /evidence/uploads on Render.
BACKEND_DIR = Path(__file__).resolve().parents[2]

UPLOAD_DIR = Path(
    os.environ.get(
        "EVIDENCE_UPLOAD_DIR",
        str(BACKEND_DIR / "evidence" / "uploads"),
    )
)


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

    # Create the upload directory if it does not exist.
    UPLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Generate a unique stored filename while preserving the extension.
    extension = Path(upload.filename).suffix.lower()

    stored_filename = (
        f"{uuid.uuid4().hex}{extension}"
    )

    destination = UPLOAD_DIR / stored_filename

    # Calculate SHA-256 and file size while saving in chunks.
    sha256 = hashlib.sha256()
    file_size = 0

    try:
        with destination.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                output.write(chunk)
                sha256.update(chunk)
                file_size += len(chunk)
    except Exception:
        # Remove an incomplete file if saving fails.
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()

    return (
        stored_filename,
        sha256.hexdigest(),
        file_size,
    )
