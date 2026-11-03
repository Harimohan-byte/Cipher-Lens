"""Prompt-hash caching for LLM completions (Task A10).

Saves quota by caching LLM responses by SHA-256 hash of (system, user, schema).
"""

import hashlib
import json
from pathlib import Path


class PromptCache:
    """Caches LLM completion outputs by SHA-256 prompt hash."""

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: dict[str, str] = {}

    @staticmethod
    def compute_hash(system: str, user: str, schema_name: str) -> str:
        """Computes deterministic SHA-256 hash of system prompt, user prompt, and schema name."""
        content = f"{system.strip()}||{user.strip()}||{schema_name}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(self, prompt_hash: str) -> str | None:
        """Looks up cached raw response string."""
        if prompt_hash in self._memory_cache:
            return self._memory_cache[prompt_hash]

        if self.cache_dir:
            file_path = self.cache_dir / f"{prompt_hash}.json"
            if file_path.exists():
                try:
                    data = json.loads(file_path.read_text(encoding="utf-8"))
                    text = data.get("response")
                    if text:
                        self._memory_cache[prompt_hash] = text
                        return text
                except Exception:
                    pass
        return None

    def set(self, prompt_hash: str, response_text: str) -> None:
        """Stores response in memory and on disk."""
        self._memory_cache[prompt_hash] = response_text
        if self.cache_dir:
            try:
                file_path = self.cache_dir / f"{prompt_hash}.json"
                file_path.write_text(
                    json.dumps(
                        {"hash": prompt_hash, "response": response_text}, indent=2
                    ),
                    encoding="utf-8",
                )
            except Exception:
                pass
