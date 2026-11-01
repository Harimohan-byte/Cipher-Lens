"""Evidence and raw artifact storage with SHA-256 integrity verification."""

import hashlib
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class ArtifactMetadata(BaseModel):
    """Metadata for a securely stored raw tool output artifact."""
    artifact_id: str
    source_tool: str
    run_id: str
    sha256_hash: str
    size_bytes: int
    file_path: str
    created_at: datetime


class ArtifactStore:
    """Manages raw scan artifacts and cryptographic integrity checks."""

    def __init__(self, base_dir: Path | str = "local_data/artifacts") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_raw(
        self,
        content: str | bytes,
        source_tool: str,
        run_id: str,
        extension: str = "txt",
    ) -> ArtifactMetadata:
        """Saves raw tool output unmodified, computing SHA-256 and restricting file permissions."""
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)

        # Unique artifact ID with timestamp prefix
        timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:8]
        artifact_id = f"art_{timestamp_str}_{unique_suffix}"

        safe_ext = extension.lstrip(".")
        filename = f"{artifact_id}.{safe_ext}"
        target_path = self.base_dir / filename

        # Write content atomically
        with open(target_path, "wb") as f:
            f.write(raw_bytes)

        # Restrict permissions if supported (POSIX read-only for owner)
        try:
            if hasattr(os, "chmod"):
                os.chmod(target_path, 0o600)
        except OSError:
            pass  # Fallback gracefully on Windows filesystems where chmod 0o600 has limited effect

        return ArtifactMetadata(
            artifact_id=artifact_id,
            source_tool=source_tool,
            run_id=run_id,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            file_path=str(target_path),
            created_at=datetime.now(UTC),
        )

    def get_path(self, artifact_id: str) -> Path:
        """Finds the local path for an artifact ID."""
        matches = list(self.base_dir.glob(f"{artifact_id}.*"))
        if not matches:
            raise FileNotFoundError(f"Artifact {artifact_id} not found in {self.base_dir}")
        return matches[0]

    def read_raw(self, artifact_id: str) -> bytes:
        """Reads raw bytes for an artifact."""
        path = self.get_path(artifact_id)
        with open(path, "rb") as f:
            return f.read()

    def verify(self, artifact_id: str, expected_sha256: str) -> bool:
        """Verifies an artifact's cryptographic integrity against the expected SHA-256."""
        try:
            content = self.read_raw(artifact_id)
            current_hash = hashlib.sha256(content).hexdigest()
            return current_hash.lower() == expected_sha256.lower()
        except (FileNotFoundError, OSError):
            return False

    @staticmethod
    def build_locator(artifact_id: str, inner_locator: str) -> str:
        """Formats standard locator string: artifact_id#locator."""
        return f"{artifact_id}#{inner_locator}"

    @staticmethod
    def parse_locator(full_locator: str) -> tuple[str, str]:
        """Parses standard locator string into (artifact_id, inner_locator)."""
        if "#" not in full_locator:
            raise ValueError(f"Invalid locator format '{full_locator}', expected 'artifact_id#locator'")
        artifact_id, inner = full_locator.split("#", 1)
        return artifact_id, inner
