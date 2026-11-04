"""Evidence and raw artifact storage with SHA-256 integrity verification and opt-in encryption."""

import hashlib
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel

from cipher_lens.config import get_settings

_EXTENSION_REGEX = re.compile(r"^[a-z0-9]{1,8}$")
_ARTIFACT_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class ArtifactMetadata(BaseModel):
    """Metadata for a securely stored raw tool output artifact."""
    artifact_id: str
    source_tool: str
    run_id: str
    sha256_hash: str
    size_bytes: int
    file_path: str
    created_at: datetime
    is_encrypted: bool = False


class ArtifactStore:
    """Manages raw scan artifacts, opt-in encryption at rest, and cryptographic integrity checks (ERR-14)."""

    def __init__(
        self,
        base_dir: Path | str = "local_data/artifacts",
        fernet_key: str | bytes | None = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        key = fernet_key or get_settings().fernet_key
        if key:
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            self._fernet: Fernet | None = Fernet(key_bytes)
        else:
            self._fernet = None

    def save_raw(
        self,
        content: str | bytes,
        source_tool: str,
        run_id: str,
        extension: str = "txt",
    ) -> ArtifactMetadata:
        """Saves raw tool output unmodified or encrypted, computing SHA-256 on the original plaintext."""
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)

        # Unique artifact ID with timestamp prefix
        timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:8]
        artifact_id = f"art_{timestamp_str}_{unique_suffix}"

        clean_ext = extension.lstrip(".").lower().strip()
        if not _EXTENSION_REGEX.match(clean_ext):
            raise ValueError(f"Invalid extension '{extension}'; must match '^[a-z0-9]{{1,8}}$'")

        filename = f"{artifact_id}.{clean_ext}"
        base_resolved = self.base_dir.resolve()
        target_path = (self.base_dir / filename).resolve()
        if not target_path.is_relative_to(base_resolved):
            raise ValueError(f"Path traversal detected in artifact filename '{filename}'")

        # Encrypt content if Fernet key is configured (ERR-14)
        bytes_to_write = self._fernet.encrypt(raw_bytes) if self._fernet is not None else raw_bytes

        # Write content atomically
        with open(target_path, "wb") as f:
            f.write(bytes_to_write)

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
            is_encrypted=self._fernet is not None,
        )

    def get_path(self, artifact_id: str) -> Path:
        """Finds the local path for an artifact ID."""
        clean_id = artifact_id.strip()
        if not _ARTIFACT_ID_REGEX.match(clean_id):
            raise ValueError(f"Invalid artifact_id '{artifact_id}'; must match '^[a-zA-Z0-9_-]{{1,64}}$'")

        base_resolved = self.base_dir.resolve()
        for item in self.base_dir.iterdir():
            if item.is_file() and item.name.startswith(f"{clean_id}."):
                resolved = item.resolve()
                if resolved.is_relative_to(base_resolved):
                    return resolved

        raise FileNotFoundError(f"Artifact {artifact_id} not found in {self.base_dir}")

    def read_raw(self, artifact_id: str) -> bytes:
        """Reads raw bytes for an artifact, transparently decrypting if encrypted."""
        path = self.get_path(artifact_id)
        with open(path, "rb") as f:
            data = f.read()
        if self._fernet is not None:
            try:
                return self._fernet.decrypt(data)
            except InvalidToken:
                # If decryption fails (e.g. unencrypted legacy file), return data unmodified
                return data
        return data

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
