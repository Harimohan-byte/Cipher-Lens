# DECISION: this detects edited rows, middle deletions and reordering, but NOT truncation of the tail or a full rewrite; head_hash exists so the UI and report can display it.
"""Append-only, hash-chained audit logging and verification for Cipher-Lens."""

import hashlib
import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """Serializes a Python object into canonical JSON with sorted keys and no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class AuditEvent:
    """An immutable record of a state transition or critical action in the system."""

    id: int
    ts: str
    actor: str
    event_type: str
    assessment_id: str | None
    payload: dict[str, Any]
    prev_hash: str
    row_hash: str


@dataclass(frozen=True)
class ChainVerification:
    """Results from cryptographic verification of the audit log hash chain."""

    ok: bool
    rows_checked: int
    first_bad_id: int | None
    reason: str
    head_hash: str


class EventPublisher:
    """Distributes committed audit events to registered subscriber callbacks."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[AuditEvent], None]] = []

    def subscribe(self, callback: Callable[[AuditEvent], None]) -> None:
        """Registers a callback to receive newly committed audit events."""
        self._subscribers.append(callback)

    def publish(self, event: AuditEvent) -> None:
        """Notifies all registered subscribers of a newly committed event.

        Subscriber exceptions are caught and logged, never preventing other subscribers
        from executing or invalidating the committed event.
        """
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception:
                # DECISION: this is the only place a broad "except Exception" is allowed; never write a bare "except:".
                logger.exception("Audit subscriber %r failed for event %s", callback, event.id)


class AuditLog:
    """Append-only, hash-chained audit trail backed by SQLite."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        publisher: EventPublisher | None = None,
    ) -> None:
        self.conn = conn
        self.publisher = publisher

    def append(
        self,
        *,
        actor: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        assessment_id: str | None = None,
    ) -> AuditEvent:
        """Appends an event to the audit trail and publishes it to subscribers.

        Never put secrets or raw scan output in audit payloads.
        """
        if not isinstance(actor, str):
            raise TypeError("actor must be a string")
        if not actor:
            raise ValueError("actor must be a non-empty string")

        if not isinstance(event_type, str):
            raise TypeError("event_type must be a string")
        if not event_type:
            raise ValueError("event_type must be a non-empty string")

        if assessment_id is not None and not isinstance(assessment_id, str):
            raise TypeError("assessment_id must be a string or None")

        payload_obj = {} if payload is None else payload
        if not isinstance(payload_obj, dict):
            raise TypeError("payload must be a dict or None")

        try:
            payload_text = canonical_json(payload_obj)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"payload is not JSON-serializable: {exc}") from exc

        cursor = self.conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            cursor.execute("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            last_row = cursor.fetchone()
            if last_row is None:
                last_id = 0
                prev_hash = GENESIS_HASH
            else:
                last_id = last_row[0]
                prev_hash = last_row[1]

            new_id = last_id + 1
            ts = datetime.now(UTC).isoformat(timespec="microseconds")
            row_dict = {
                "id": new_id,
                "ts": ts,
                "actor": actor,
                "event_type": event_type,
                "assessment_id": assessment_id,
                "payload": payload_obj,
            }
            row_hash = hashlib.sha256(
                (prev_hash + canonical_json(row_dict)).encode("utf-8")
            ).hexdigest()

            cursor.execute(
                "INSERT INTO audit_log (id, ts, actor, event_type, assessment_id, payload, prev_hash, row_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (new_id, ts, actor, event_type, assessment_id, payload_text, prev_hash, row_hash),
            )
            cursor.execute("COMMIT")
        except Exception:
            cursor.execute("ROLLBACK")
            raise

        event = AuditEvent(
            id=new_id,
            ts=ts,
            actor=actor,
            event_type=event_type,
            assessment_id=assessment_id,
            payload=payload_obj,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )

        if self.publisher is not None:
            self.publisher.publish(event)

        return event

    def query(
        self,
        assessment_id: str | None = None,
        event_type: str | None = None,
        actor: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        """Queries audit events by assessment_id, event_type, and/or actor in insertion order."""
        query_sql = "SELECT id, ts, actor, event_type, assessment_id, payload, prev_hash, row_hash FROM audit_log"
        conditions: list[str] = []
        params: list[Any] = []

        if assessment_id is not None:
            conditions.append("assessment_id = ?")
            params.append(assessment_id)
        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)
        if actor is not None:
            conditions.append("actor = ?")
            params.append(actor)

        if conditions:
            query_sql += " WHERE " + " AND ".join(conditions)

        query_sql += " ORDER BY id ASC"
        if limit is not None:
            query_sql += f" LIMIT {int(limit)}"

        cursor = self.conn.cursor()
        cursor.execute(query_sql, params)
        rows = cursor.fetchall()
        events: list[AuditEvent] = []
        for r in rows:
            payload_data = json.loads(r[5]) if r[5] else {}
            events.append(
                AuditEvent(
                    id=r[0],
                    ts=r[1],
                    actor=r[2],
                    event_type=r[3],
                    assessment_id=r[4],
                    payload=payload_data,
                    prev_hash=r[6],
                    row_hash=r[7],
                )
            )
        return events

    def verify_chain(self, expected_head_hash: str | None = None) -> ChainVerification:
        """Verifies the integrity of the entire audit chain.

        Never raises on tampering; returns ok=False with first_bad_id and a readable reason.
        If expected_head_hash is provided, verifies that the chain terminates at that exact hash.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, ts, actor, event_type, assessment_id, payload, prev_hash, row_hash "
            "FROM audit_log ORDER BY id ASC"
        )
        rows = cursor.fetchall()

        if not rows:
            ok = expected_head_hash is None or expected_head_hash == GENESIS_HASH
            return ChainVerification(
                ok=ok,
                rows_checked=0,
                first_bad_id=None if ok else 0,
                reason="Log is empty" if ok else f"Empty log head_hash mismatch: expected {expected_head_hash}",
                head_hash=GENESIS_HASH,
            )

        head_hash = rows[-1][7]
        expected_id = 1
        expected_prev_hash = GENESIS_HASH

        for idx, (
            row_id,
            ts,
            actor,
            event_type,
            assessment_id,
            payload_text,
            prev_hash,
            row_hash,
        ) in enumerate(rows):
            if row_id != expected_id:
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=f"Non-contiguous id: expected {expected_id}, found {row_id}",
                    head_hash=head_hash,
                )

            if prev_hash != expected_prev_hash:
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=(
                        f"Hash chain broken at row {row_id}: "
                        f"expected prev_hash {expected_prev_hash}, found {prev_hash}"
                    ),
                    head_hash=head_hash,
                )

            try:
                parsed_payload = json.loads(payload_text)
            except Exception as exc:
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=f"Invalid payload JSON at row {row_id}: {exc}",
                    head_hash=head_hash,
                )

            if not isinstance(parsed_payload, dict):
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=f"Payload at row {row_id} is not a JSON object/dict",
                    head_hash=head_hash,
                )

            if canonical_json(parsed_payload) != payload_text:
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=f"Payload text at row {row_id} is not canonical JSON",
                    head_hash=head_hash,
                )

            row_dict = {
                "id": row_id,
                "ts": ts,
                "actor": actor,
                "event_type": event_type,
                "assessment_id": assessment_id,
                "payload": parsed_payload,
            }
            recomputed_hash = hashlib.sha256(
                (prev_hash + canonical_json(row_dict)).encode("utf-8")
            ).hexdigest()

            if row_hash != recomputed_hash:
                return ChainVerification(
                    ok=False,
                    rows_checked=idx,
                    first_bad_id=row_id,
                    reason=(
                        f"Row hash mismatch at row {row_id}: "
                        f"expected {recomputed_hash}, found {row_hash}"
                    ),
                    head_hash=head_hash,
                )

            expected_id += 1
            expected_prev_hash = row_hash

        if expected_head_hash is not None and head_hash != expected_head_hash:
            return ChainVerification(
                ok=False,
                rows_checked=len(rows),
                first_bad_id=rows[-1][0],
                reason=f"Head hash mismatch: expected {expected_head_hash}, found {head_hash}",
                head_hash=head_hash,
            )

        return ChainVerification(
            ok=True,
            rows_checked=len(rows),
            first_bad_id=None,
            reason="Chain verified successfully",
            head_hash=head_hash,
        )

