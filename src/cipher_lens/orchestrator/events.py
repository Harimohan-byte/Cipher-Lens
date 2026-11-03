"""In-memory event bus and streaming event models for assessment UI and orchestrator."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class AssessmentEvent(BaseModel):
    """Event emitted during assessment lifecycle."""

    event_id: str
    assessment_id: str
    event_type: str  # plan_proposed, step_started, step_finished, approval_needed, finding_correlated, replan
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EventBus:
    """Pub/Sub event broker for streaming orchestrator events to UI and listeners."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[AssessmentEvent], None]] = []

    def subscribe(self, callback: Callable[[AssessmentEvent], None]) -> None:
        """Registers a listener callback."""
        self._subscribers.append(callback)

    def publish(self, event: AssessmentEvent) -> None:
        """Delivers event to all registered subscribers."""
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass  # Subscriber failure never breaks orchestrator flow

