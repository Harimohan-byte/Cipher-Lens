"""Tests for the integration matrix generator (B8).

The matrix MUST reflect actual healthcheck truth:
- An adapter may only appear as 'live' if its binary was found.
- An adapter appearing as 'unavailable' must never be promoted to 'live'.
"""



def test_matrix_reflects_healthcheck_unavailable(monkeypatch):
    """If a binary is not on PATH, matrix must show 'unavailable', not 'live'."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)

    from cipher_lens.adapters.matrix import build_matrix

    matrix = build_matrix()
    for entry in matrix:
        assert entry["status"] == "unavailable", (
            f"Adapter '{entry['name']}' claims '{entry['status']}' but binary is not found"
        )


def test_matrix_reflects_healthcheck_healthy(monkeypatch):
    """If binaries are available, matrix shows 'healthy' status."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    from cipher_lens.adapters.matrix import build_matrix

    matrix = build_matrix()
    for entry in matrix:
        assert entry["status"] == "healthy", (
            f"Adapter '{entry['name']}' should be 'healthy' but got '{entry['status']}'"
        )


def test_matrix_cannot_overclaim(monkeypatch):
    """Safety: No adapter can appear as 'healthy' if its binary is missing.

    This test fails if the matrix overclaims adapter availability.
    """
    import shutil

    # Only allow nmap, not nikto
    def selective_which(name: str):
        return f"/usr/bin/{name}" if name == "nmap" else None

    monkeypatch.setattr(shutil, "which", selective_which)

    from cipher_lens.adapters.matrix import build_matrix

    matrix = build_matrix()
    nmap_entry = next((e for e in matrix if e["name"] == "nmap"), None)
    nikto_entry = next((e for e in matrix if e["name"] == "nikto"), None)

    assert nmap_entry is not None, "nmap should appear in the matrix"
    assert nikto_entry is not None, "nikto should appear in the matrix"
    assert nmap_entry["status"] == "healthy"
    assert nikto_entry["status"] == "unavailable"


def test_matrix_generates_markdown(monkeypatch):
    """Matrix renders to a valid markdown table with correct headers."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)

    from cipher_lens.adapters.matrix import build_matrix, render_markdown

    matrix = build_matrix()
    md = render_markdown(matrix)

    assert "| Adapter |" in md
    assert "| Status |" in md
    assert "nmap" in md
    assert "nikto" in md
    assert "zap" in md
    assert "burp_import" in md
    assert "nessus_import" in md
    assert "openvas_import" in md
    # Must be a proper markdown table (separator row)
    assert "|---" in md or "| ---" in md or "|:---" in md


def test_matrix_entries_have_required_fields(monkeypatch):
    """Each matrix entry must contain name, status, and description fields."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)

    from cipher_lens.adapters.matrix import build_matrix

    matrix = build_matrix()
    assert len(matrix) >= 6, "Matrix must include nmap, nikto, zap, and 3 report importers"

    names = {e["name"] for e in matrix}
    assert {"nmap", "nikto", "zap", "burp_import", "nessus_import", "openvas_import"}.issubset(names)

    for entry in matrix:
        assert "name" in entry
        assert "status" in entry
        assert "description" in entry
        assert entry["status"] in ("healthy", "unavailable", "degraded")
