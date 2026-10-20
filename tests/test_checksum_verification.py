import tempfile
from pathlib import Path
import pytest
from scripts.verify_release_checksum import (
    compute_sha256,
    generate_checksum_file,
    verify_checksum_file
)


def test_checksum_generation_and_valid_verification():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        artifact = tmp_path / "test_app.exe"
        checksum_file = tmp_path / "SHA256SUMS.txt"

        # Create dummy binary
        artifact.write_bytes(b"\x90\x00\x01\x02FakeExecutableBinaryData" * 100)

        digest = generate_checksum_file(artifact, checksum_file)
        assert len(digest) == 64
        assert checksum_file.exists()

        # Verify checksum file matches
        assert verify_checksum_file(checksum_file) is True


def test_checksum_mismatch_detected():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        artifact = tmp_path / "test_app.exe"
        checksum_file = tmp_path / "SHA256SUMS.txt"

        artifact.write_bytes(b"OriginalContent")
        generate_checksum_file(artifact, checksum_file)

        # Alter binary content
        artifact.write_bytes(b"TamperedContent")
        assert verify_checksum_file(checksum_file) is False


def test_checksum_malformed_format_rejected():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        checksum_file = tmp_path / "SHA256SUMS.txt"
        checksum_file.write_text("invalid_format_without_digest", encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid format"):
            verify_checksum_file(checksum_file)


def test_checksum_missing_artifact_raises():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        checksum_file = tmp_path / "SHA256SUMS.txt"
        checksum_file.write_text("a" * 64 + "  nonexistent.exe\n", encoding="utf-8")

        with pytest.raises(FileNotFoundError, match="not found"):
            verify_checksum_file(checksum_file)
