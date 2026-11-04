"""Tests for audit log storage, hash chaining, tamper detection, and concurrency."""

import hashlib
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from cipher_lens.store.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditLog,
    EventPublisher,
    canonical_json,
)
from cipher_lens.store.db import connect, init_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Fixture providing a real database file path in a temporary directory."""
    return tmp_path / "test_audit.db"


@pytest.fixture
def db_conn(db_path: Path) -> sqlite3.Connection:
    """Fixture providing an initialized SQLite connection with tables and triggers."""
    conn = connect(db_path)
    init_db(conn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def audit_log(db_conn: sqlite3.Connection) -> AuditLog:
    """Fixture providing an AuditLog instance."""
    return AuditLog(db_conn)


def test_100_appended_rows_verify_ok(audit_log: AuditLog):
    """Test 1: 100 appended rows verify ok: rows_checked == 100 and head_hash equals last row's row_hash."""
    last_event: AuditEvent | None = None
    for i in range(100):
        last_event = audit_log.append(
            actor="test-runner",
            event_type="test_event",
            payload={"index": i, "status": "active"},
            assessment_id="asmt-001",
        )

    assert last_event is not None
    assert last_event.id == 100

    result = audit_log.verify_chain()
    assert result.ok is True
    assert result.rows_checked == 100
    assert result.first_bad_id is None
    assert result.head_hash == last_event.row_hash


def test_empty_log_verifies_ok(audit_log: AuditLog):
    """Test 2: Empty log verifies ok with rows_checked == 0 and head_hash == GENESIS_HASH."""
    result = audit_log.verify_chain()
    assert result.ok is True
    assert result.rows_checked == 0
    assert result.first_bad_id is None
    assert result.head_hash == GENESIS_HASH


def test_first_row_genesis_and_chain_linkage(audit_log: AuditLog):
    """Test 3: First row's prev_hash is GENESIS_HASH and every later prev_hash equals previous row_hash."""
    events = [
        audit_log.append(
            actor="analyst",
            event_type=f"event_{i}",
            payload={"step": i},
            assessment_id="asmt-chain",
        )
        for i in range(5)
    ]

    assert events[0].prev_hash == GENESIS_HASH
    for i in range(1, len(events)):
        assert events[i].prev_hash == events[i - 1].row_hash


@pytest.mark.parametrize(
    "tamper_column,tampered_val",
    [
        ("payload", '{"tampered":true}'),
        ("actor", "malicious_actor"),
        ("ts", "2020-01-01T00:00:00.000000+00:00"),
        ("event_type", "tampered_event"),
        ("assessment_id", "tampered_asmt"),
        ("row_hash", "0" * 63 + "1"),
    ],
)
def test_tamper_detection_break_it_check(
    db_conn: sqlite3.Connection,
    audit_log: AuditLog,
    tamper_column: str,
    tampered_val: str,
):
    """Test 4: Tamper detection parametrized over all columns.

    Safety break-it check: dropping no_update trigger and tampering must fail verify_chain.
    """
    for i in range(1, 4):
        audit_log.append(
            actor="analyst",
            event_type=f"event_{i}",
            payload={"step": i},
            assessment_id="asmt-tamper",
        )

    # Disable update protection trigger to simulate database file tampering at rest
    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_update")

    # Tamper with row id = 2
    cursor.execute(
        f"UPDATE audit_log SET {tamper_column} = ? WHERE id = 2",
        (tampered_val,),
    )

    result = audit_log.verify_chain()
    assert result.ok is False
    assert result.first_bad_id == 2


def test_tampered_non_dict_payload_fails_verification(
    db_conn: sqlite3.Connection, audit_log: AuditLog
):
    """Vulnerability test: non-dict JSON payload (array, string, int) must fail verify_chain."""
    for i in range(1, 3):
        audit_log.append(actor="tester", event_type="dict_test", payload={"step": i})

    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    cursor.execute("UPDATE audit_log SET payload = '[1, 2, 3]' WHERE id = 2")

    result = audit_log.verify_chain()
    assert result.ok is False
    assert result.first_bad_id == 2


def test_verify_chain_with_expected_head_hash(audit_log: AuditLog):
    """Test verifying chain against expected_head_hash to protect against tail tampering."""
    event1 = audit_log.append(actor="tester", event_type="e1", payload={"step": 1})
    event2 = audit_log.append(actor="tester", event_type="e2", payload={"step": 2})

    # Correct head_hash verifies ok
    assert audit_log.verify_chain(expected_head_hash=event2.row_hash).ok is True

    # Stale/incorrect head_hash fails
    mismatch = audit_log.verify_chain(expected_head_hash=event1.row_hash)
    assert mismatch.ok is False
    assert "Head hash mismatch" in mismatch.reason


def test_rewired_prev_hash_detected(db_conn: sqlite3.Connection, audit_log: AuditLog):
    """Test 5: A rewired prev_hash is detected even if the row's row_hash is recomputed."""
    for i in range(1, 4):
        audit_log.append(
            actor="analyst",
            event_type=f"event_{i}",
            payload={"step": i},
            assessment_id="asmt-rewire",
        )

    # Drop trigger to manipulate rows directly
    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_update")

    # Read row 2 to recompute with forged prev_hash
    cursor.execute(
        "SELECT id, ts, actor, event_type, assessment_id, payload FROM audit_log WHERE id = 2"
    )
    row_data = cursor.fetchone()
    row_dict = {
        "id": row_data[0],
        "ts": row_data[1],
        "actor": row_data[2],
        "event_type": row_data[3],
        "assessment_id": row_data[4],
        "payload": json.loads(row_data[5]),
    }

    bogus_prev_hash = "f" * 64
    forged_row_hash = hashlib.sha256(
        (bogus_prev_hash + canonical_json(row_dict)).encode("utf-8")
    ).hexdigest()

    cursor.execute(
        "UPDATE audit_log SET prev_hash = ?, row_hash = ? WHERE id = 2",
        (bogus_prev_hash, forged_row_hash),
    )

    result = audit_log.verify_chain()
    assert result.ok is False
    assert result.first_bad_id == 2


def test_middle_deletion_and_reordering_detected(
    db_conn: sqlite3.Connection, audit_log: AuditLog
):
    """Test 6: Middle deletion and swapped ids (reordering) are detected."""
    # 6a: Middle deletion
    for i in range(1, 4):
        audit_log.append(
            actor="analyst",
            event_type=f"event_{i}",
            payload={"step": i},
            assessment_id="asmt-delete",
        )

    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    cursor.execute("DELETE FROM audit_log WHERE id = 2")

    result = audit_log.verify_chain()
    assert result.ok is False
    assert result.first_bad_id == 3

    # 6b: Swapping two row IDs (reordering)
    # Clear and re-populate
    cursor.execute("DELETE FROM audit_log")
    for i in range(1, 4):
        audit_log.append(
            actor="analyst",
            event_type=f"event_{i}",
            payload={"step": i},
            assessment_id="asmt-swap",
        )

    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    cursor.execute("UPDATE audit_log SET id = 999 WHERE id = 1")
    cursor.execute("UPDATE audit_log SET id = 1 WHERE id = 2")
    cursor.execute("UPDATE audit_log SET id = 2 WHERE id = 999")

    result_swap = audit_log.verify_chain()
    assert result_swap.ok is False
    # Row with id=1 is now former row 2, which fails verification
    assert result_swap.first_bad_id == 1


def test_triggers_block_update_and_delete(audit_log: AuditLog, db_conn: sqlite3.Connection):
    """Test 7: With triggers in place, raw UPDATE and DELETE raise sqlite3.IntegrityError."""
    audit_log.append(
        actor="analyst",
        event_type="event_lock",
        payload={"immutable": True},
        assessment_id="asmt-triggers",
    )

    cursor = db_conn.cursor()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        cursor.execute("UPDATE audit_log SET actor = 'rogue' WHERE id = 1")

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        cursor.execute("DELETE FROM audit_log WHERE id = 1")


def test_canonical_json_ordering_and_nan():
    """Test 8: canonical_json is identical for different key order and rejects NaN."""
    d1 = {"b": 2, "a": 1, "c": {"y": "yes", "x": "no"}}
    d2 = {"a": 1, "c": {"x": "no", "y": "yes"}, "b": 2}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == '{"a":1,"b":2,"c":{"x":"no","y":"yes"}}'

    with pytest.raises(ValueError):
        canonical_json({"val": float("nan")})


def test_non_ascii_payload_roundtrip(audit_log: AuditLog):
    """Test 9: Non-ASCII text round-trips correctly and the chain verifies."""
    payload = {
        "japanese": "セキュリティ診断",
        "german": "Überprüfung für Schwachstellen",
        "symbols": "«Cipher-Lens» — 🛡️",
    }
    event = audit_log.append(
        actor="multilingual_analyst",
        event_type="i18n_test",
        payload=payload,
        assessment_id="asmt-utf8",
    )

    assert event.payload == payload
    verification = audit_log.verify_chain()
    assert verification.ok is True
    assert verification.rows_checked == 1


def test_concurrent_appends_two_threads(db_path: Path):
    """Test 10: Two threads with separate connections append 50 events each; all 100 verify."""
    init_conn = connect(db_path)
    init_db(init_conn)
    init_conn.close()

    events_per_thread = 50
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def worker(worker_id: int):
        conn = connect(db_path)
        log = AuditLog(conn)
        try:
            barrier.wait()
            for i in range(events_per_thread):
                log.append(
                    actor=f"worker-{worker_id}",
                    event_type="concurrent_append",
                    payload={"worker": worker_id, "seq": i},
                    assessment_id="asmt-concurrency",
                )
        except Exception as exc:  # Thread exception capture for test assertion
            errors.append(exc)
        finally:
            conn.close()

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Thread errors occurred: {errors}"

    verify_conn = connect(db_path)
    try:
        verify_log = AuditLog(verify_conn)
        verification = verify_log.verify_chain()
        assert verification.ok is True
        assert verification.rows_checked == 100
        assert verification.first_bad_id is None

        cursor = verify_conn.cursor()
        cursor.execute("SELECT id FROM audit_log ORDER BY id ASC")
        ids = [row[0] for row in cursor.fetchall()]
        assert ids == list(range(1, 101))
    finally:
        verify_conn.close()


def test_publisher_notifications_and_isolation(db_conn: sqlite3.Connection, db_path: Path):
    """Test 11: Publisher notifications, post-commit readability, and exception isolation."""
    publisher = EventPublisher()
    received_events: list[AuditEvent] = []
    second_conn_checks: list[bool] = []

    def sub_verify_committed(event: AuditEvent):
        # Verify the event is already committed and visible to an independent connection
        other_conn = connect(db_path)
        try:
            cur = other_conn.cursor()
            cur.execute("SELECT id, row_hash FROM audit_log WHERE id = ?", (event.id,))
            row = cur.fetchone()
            second_conn_checks.append(row is not None and row[0] == event.id)
        finally:
            other_conn.close()

    def sub_exploding(event: AuditEvent):
        raise RuntimeError("Subscriber explosion test")

    def sub_recording(event: AuditEvent):
        received_events.append(event)

    publisher.subscribe(sub_verify_committed)
    publisher.subscribe(sub_exploding)
    publisher.subscribe(sub_recording)

    log = AuditLog(db_conn, publisher=publisher)

    # 1. Validation failure does not invoke publisher
    with pytest.raises(ValueError):
        log.append(actor="", event_type="invalid_test")
    assert len(received_events) == 0

    # 2. Successful append calls subscribers; sub_exploding does not block sub_recording or append
    event = log.append(
        actor="publisher-tester",
        event_type="pub_event",
        payload={"test": "publisher"},
        assessment_id="asmt-pub",
    )

    assert len(received_events) == 1
    assert received_events[0].id == event.id
    assert len(second_conn_checks) == 1
    assert second_conn_checks[0] is True


def test_append_input_validation(audit_log: AuditLog, db_conn: sqlite3.Connection):
    """Test 12: Validation for empty actor/event_type, non-dict/non-serializable payload."""
    invalid_cases = [
        {"actor": "", "event_type": "valid"},
        {"actor": 123, "event_type": "valid"},
        {"actor": "valid", "event_type": ""},
        {"actor": "valid", "event_type": None},
        {"actor": "valid", "event_type": "valid", "payload": "not_a_dict"},
        {"actor": "valid", "event_type": "valid", "payload": [1, 2, 3]},
        {"actor": "valid", "event_type": "valid", "payload": {"nan": float("nan")}},
        {"actor": "valid", "event_type": "valid", "assessment_id": 999},
    ]

    for kwargs in invalid_cases:
        with pytest.raises((ValueError, TypeError)):
            audit_log.append(**kwargs)

    cursor = db_conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    assert cursor.fetchone()[0] == 0


def test_init_db_idempotency(db_conn: sqlite3.Connection):
    """Test 13: Calling init_db multiple times neither fails nor modifies existing data."""
    log = AuditLog(db_conn)
    log.append(actor="tester", event_type="init_test", payload={"key": "val"})

    # Call init_db again on the already initialized database
    init_db(db_conn)
    init_db(db_conn)

    verification = log.verify_chain()
    assert verification.ok is True
    assert verification.rows_checked == 1


def test_checkpoint_write_and_verify_ok(audit_log: AuditLog, tmp_path: Path):
    """Test 14: Writing an external checkpoint anchor and verifying it succeeds."""
    ckpt_path = tmp_path / "checkpoint.json"
    for i in range(5):
        audit_log.append(actor="tester", event_type="ckpt_test", payload={"i": i})

    head_hash = audit_log.write_checkpoint(ckpt_path)
    assert ckpt_path.is_file()

    result = audit_log.verify_checkpoint(ckpt_path)
    assert result.ok is True
    assert result.rows_checked == 5
    assert result.head_hash == head_hash


def test_checkpoint_tail_truncation_detected_break_it(
    db_conn: sqlite3.Connection, audit_log: AuditLog, tmp_path: Path
):
    """Test 15 (ERR-21 Break-it): Tail truncation is undetected by internal verify_chain,

    but MUST be detected by verify_checkpoint.
    """
    ckpt_path = tmp_path / "checkpoint.json"
    for i in range(1, 6):
        audit_log.append(actor="tester", event_type="trunc_test", payload={"i": i})

    audit_log.write_checkpoint(ckpt_path)

    # Attacker drops DELETE trigger and truncates rows 4 and 5
    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    cursor.execute("DELETE FROM audit_log WHERE id >= 4")

    # Internal chain verification passes for remaining 3 rows!
    internal_res = audit_log.verify_chain()
    assert internal_res.ok is True
    assert internal_res.rows_checked == 3

    # But external checkpoint verification detects the truncation attack!
    external_res = audit_log.verify_checkpoint(ckpt_path)
    assert external_res.ok is False
    assert "truncated" in external_res.reason.lower()
    assert external_res.rows_checked == 3


def test_checkpoint_rewrite_recomputation_detected_break_it(
    db_conn: sqlite3.Connection, audit_log: AuditLog, tmp_path: Path
):
    """Test 16 (ERR-21 Break-it): Chain rewritten and recomputed passes internal verify_chain,

    but MUST fail verify_checkpoint against the external anchor.
    """
    ckpt_path = tmp_path / "checkpoint.json"
    for i in range(1, 4):
        audit_log.append(actor="tester", event_type="rewrite_test", payload={"i": i})

    audit_log.write_checkpoint(ckpt_path)

    # Attacker drops UPDATE trigger, modifies row 2, and recomputes hashes forward
    cursor = db_conn.cursor()
    cursor.execute("DROP TRIGGER IF EXISTS audit_log_no_update")

    # Modify row 2
    cursor.execute("SELECT ts, actor, event_type, assessment_id FROM audit_log WHERE id = 2")
    ts2, actor2, ev2, asmt2 = cursor.fetchone()
    # Row 1's hash is unchanged
    cursor.execute("SELECT row_hash FROM audit_log WHERE id = 1")
    row1_hash = cursor.fetchone()[0]

    forged_payload2 = {"i": 999}
    dict2 = {
        "id": 2,
        "ts": ts2,
        "actor": actor2,
        "event_type": ev2,
        "assessment_id": asmt2,
        "payload": forged_payload2,
    }
    recomputed_hash2 = hashlib.sha256((row1_hash + canonical_json(dict2)).encode("utf-8")).hexdigest()
    cursor.execute(
        "UPDATE audit_log SET payload = ?, prev_hash = ?, row_hash = ? WHERE id = 2",
        (canonical_json(forged_payload2), row1_hash, recomputed_hash2),
    )

    # Recompute row 3
    cursor.execute("SELECT ts, actor, event_type, assessment_id, payload FROM audit_log WHERE id = 3")
    ts3, actor3, ev3, asmt3, p3 = cursor.fetchone()
    dict3 = {
        "id": 3,
        "ts": ts3,
        "actor": actor3,
        "event_type": ev3,
        "assessment_id": asmt3,
        "payload": json.loads(p3),
    }
    recomputed_hash3 = hashlib.sha256((recomputed_hash2 + canonical_json(dict3)).encode("utf-8")).hexdigest()
    cursor.execute(
        "UPDATE audit_log SET prev_hash = ?, row_hash = ? WHERE id = 3",
        (recomputed_hash2, recomputed_hash3),
    )

    # Internal verify_chain is fooled by the recomputation!
    internal_res = audit_log.verify_chain()
    assert internal_res.ok is True

    # Checkpoint anchor detects the rewrite!
    external_res = audit_log.verify_checkpoint(ckpt_path)
    assert external_res.ok is False
    assert "mismatch" in external_res.reason.lower()


def test_checkpoint_subsequent_appends_still_verify(
    audit_log: AuditLog, tmp_path: Path
):
    """Test 17: Valid subsequent appends do not invalidate an earlier valid checkpoint anchor."""
    ckpt_path = tmp_path / "checkpoint.json"
    audit_log.append(actor="tester", event_type="e1", payload={"step": 1})
    audit_log.append(actor="tester", event_type="e2", payload={"step": 2})

    audit_log.write_checkpoint(ckpt_path)

    # Append more rows
    audit_log.append(actor="tester", event_type="e3", payload={"step": 3})
    audit_log.append(actor="tester", event_type="e4", payload={"step": 4})

    result = audit_log.verify_checkpoint(ckpt_path)
    assert result.ok is True
    assert result.rows_checked == 4


def test_checkpoint_missing_or_corrupt_fails_safely(
    audit_log: AuditLog, tmp_path: Path
):
    """Test 18: Missing or malformed checkpoint file fails cleanly with ok=False."""
    # Missing file
    res1 = audit_log.verify_checkpoint(tmp_path / "nonexistent.json")
    assert res1.ok is False
    assert "not found" in res1.reason.lower()

    # Corrupted JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    res2 = audit_log.verify_checkpoint(bad_json)
    assert res2.ok is False
    assert "malformed" in res2.reason.lower()

    # Missing fields
    missing_fields = tmp_path / "missing.json"
    missing_fields.write_text("{}", encoding="utf-8")
    res3 = audit_log.verify_checkpoint(missing_fields)
    assert res3.ok is False
    assert "missing" in res3.reason.lower()

