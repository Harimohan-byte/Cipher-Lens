"""Tests for artifact storage and evidence integrity verification."""

from pathlib import Path

import pytest

from cipher_lens.store.artifacts import ArtifactStore


@pytest.fixture
def temp_artifact_store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(base_dir=tmp_path / "artifacts")


def test_save_raw_computes_correct_sha256(temp_artifact_store: ArtifactStore):
    """Test saving raw scan data correctly hashes and stores it."""
    raw_content = b"<nmaprun>sample test output</nmaprun>"
    meta = temp_artifact_store.save_raw(
        content=raw_content,
        source_tool="nmap",
        run_id="run-123",
        extension="xml",
    )

    assert meta.source_tool == "nmap"
    assert meta.run_id == "run-123"
    assert meta.size_bytes == len(raw_content)
    # Expected SHA-256 of '<nmaprun>sample test output</nmaprun>'
    import hashlib
    expected_hash = hashlib.sha256(raw_content).hexdigest()
    assert meta.sha256_hash == expected_hash

    # Verify content read back matches
    assert temp_artifact_store.read_raw(meta.artifact_id) == raw_content

    # Verification function returns True
    assert temp_artifact_store.verify(meta.artifact_id, expected_hash) is True


def test_tamper_detection_break_it_check(temp_artifact_store: ArtifactStore):
    """Break-it check: Modifying a byte in the raw scan artifact must fail verification."""
    raw_content = "Vulnerable service detected on port 80"
    meta = temp_artifact_store.save_raw(
        content=raw_content,
        source_tool="nikto",
        run_id="run-456",
    )

    assert temp_artifact_store.verify(meta.artifact_id, meta.sha256_hash) is True

    # Tamper with the raw file directly on disk
    file_path = temp_artifact_store.get_path(meta.artifact_id)
    with open(file_path, "wb") as f:
        f.write(b"TAMPERED service detected on port 80")

    # Verification MUST fail now
    assert temp_artifact_store.verify(meta.artifact_id, meta.sha256_hash) is False


def test_locator_formatting_and_parsing(temp_artifact_store: ArtifactStore):
    """Verify standard locator format: artifact_id#locator."""
    artifact_id = "art_20261102_001"
    inner_locator = "/nmaprun/host/ports/port[1]"

    full_locator = temp_artifact_store.build_locator(artifact_id, inner_locator)
    assert full_locator == f"{artifact_id}#{inner_locator}"

    parsed_id, parsed_inner = temp_artifact_store.parse_locator(full_locator)
    assert parsed_id == artifact_id
    assert parsed_inner == inner_locator

    with pytest.raises(ValueError, match="Invalid locator format"):
        temp_artifact_store.parse_locator("invalid_locator_without_hash")
