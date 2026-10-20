import re
from pathlib import Path
from typing import Tuple
from fastapi import UploadFile, HTTPException, status
from app.config import settings

# Binary executable and archive magic headers that must never be processed as security logs
BLOCKED_MAGIC_BYTES = (
    b"MZ",                 # Windows PE EXE/DLL
    b"\x7fELF",            # Linux ELF binary
    b"\xca\xfe\xba\xbe",    # Java class / Mach-O universal
    b"\xfe\xed\xfa\xce",    # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",    # Mach-O 64-bit
    b"\xcf\xfa\xed\xfe",    # Mach-O 64-bit reverse
    b"PK\x03\x04",         # ZIP / JAR archive
    b"Rar!\x1a\x07",       # RAR archive
    b"\x1f\x8b\x08",        # GZIP compressed
    b"7z\xbc\xaf\x27\x1c", # 7-Zip archive
)

class SecureUploadHandler:
    """
    Guards file ingestion against oversized payloads, memory exhaustion,
    path traversal, binary/malware uploads, and malformed encoding.
    """

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Strips path traversal artifacts and illegal characters from filenames."""
        if not filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No filename provided in upload payload."
            )

        # Remove null bytes and directory paths
        base_name = Path(filename).name
        cleaned = re.sub(r'[\x00-\x1f\x7f/\\]', '', base_name).strip()
        if not cleaned:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename contains only illegal or empty characters."
            )

        # Check allowed extension
        ext = Path(cleaned).suffix.lower()
        if ext not in settings.ALLOWED_EXTENSIONS:
            allowed = ", ".join(sorted(settings.ALLOWED_EXTENSIONS))
            raise HTTPException(
                status_code=422,
                detail=f"Unsupported file format '{ext}'. Supported extensions: {allowed}"
            )

        return cleaned

    @classmethod
    async def read_and_validate_file(cls, file: UploadFile) -> Tuple[str, str]:
        """
        Safely streams uploaded file in chunks with strict byte limit,
        validates magic bytes, checks for text format, and returns decoded string.
        """
        filename = cls.sanitize_filename(file.filename or "")

        chunk_size = 64 * 1024  # 64 KB chunks
        total_bytes = 0
        chunks = []
        max_bytes = settings.MAX_UPLOAD_SIZE_BYTES

        first_chunk = True

        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break

            # Magic bytes check on first chunk
            if first_chunk:
                first_chunk = False
                for signature in BLOCKED_MAGIC_BYTES:
                    if chunk.startswith(signature):
                        raise HTTPException(
                            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            detail="Binary executable or archive file detected. Only plaintext security logs are accepted."
                        )

            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed upload size of {settings.MAX_UPLOAD_SIZE_MB} MB."
                )

            chunks.append(chunk)

        if total_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded log file is empty."
            )

        raw_bytes = b"".join(chunks)

        # Check for null bytes indicating binary content disguised as log
        if b"\x00" in raw_bytes[:1024]:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="File contains binary null bytes and cannot be parsed as text security logs."
            )

        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Fallback to latin-1 / cp1252 if UTF-8 fails for older Windows logs
            try:
                content = raw_bytes.decode("latin-1")
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"File encoding is not readable text: {str(e)}"
                )

        if not content.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded log file contains no readable text content."
            )

        return filename, content
