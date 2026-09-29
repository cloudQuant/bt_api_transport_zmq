"""Sequence and bounded replay primitives independent of ZMQ sockets."""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass

from .wire import WireChannel, WireMessage


class ReplayGapError(RuntimeError):
    """Requested replay starts before the bounded server buffer retains facts."""


@dataclass(frozen=True)
class SequenceObservation:
    """A message sequence result that callers can persist or turn into an alert."""

    scope: str
    sequence: int
    previous_sequence: int | None
    status: str

    @property
    def has_gap(self) -> bool:
        return self.status == "gap"


class SequenceTracker:
    """Detect duplicates and gaps without inventing missing events."""

    def __init__(self) -> None:
        self._last: dict[str, int] = {}

    def observe(self, event: WireMessage) -> SequenceObservation:
        """Observe an event.  Sequence zero is allowed for a new snapshot stream."""
        if event.channel is not WireChannel.EVENT:
            raise ValueError("SequenceTracker accepts event messages only")
        previous = self._last.get(event.scope)
        if previous is None:
            status = "initial"
        elif event.sequence == previous:
            status = "duplicate"
        elif event.sequence == previous + 1:
            status = "contiguous"
        elif event.sequence > previous + 1:
            status = "gap"
        else:
            status = "regression"
        if previous is None or event.sequence > previous:
            self._last[event.scope] = event.sequence
        return SequenceObservation(event.scope, event.sequence, previous, status)


class EventReplayBuffer:
    """A bounded server-owned replay buffer for one or more event scopes.

    It keeps transport facts only.  A caller must still reconcile authoritative
    order/account state with its single execution owner after a gap.
    """

    def __init__(self, capacity_per_scope: int = 1024) -> None:
        if capacity_per_scope <= 0:
            raise ValueError("capacity_per_scope must be positive")
        self._capacity = capacity_per_scope
        self._events: dict[str, deque[WireMessage]] = {}
        self._lock = threading.RLock()

    def append(self, event: WireMessage) -> None:
        """Append a strictly increasing event sequence for its scope."""
        if event.channel is not WireChannel.EVENT:
            raise ValueError("only event messages can enter the replay buffer")
        with self._lock:
            queue = self._events.setdefault(event.scope, deque(maxlen=self._capacity))
            if queue and event.sequence <= queue[-1].sequence:
                raise ValueError("event sequence must increase within one scope")
            queue.append(event)

    def replay_after(self, scope: str, sequence: int) -> tuple[WireMessage, ...]:
        """Return retained facts after sequence, or state that reconciliation is needed."""
        if sequence < 0:
            raise ValueError("sequence must be non-negative")
        with self._lock:
            queue = self._events.get(scope)
            if not queue:
                return ()
            oldest = queue[0].sequence
            if sequence < oldest - 1:
                raise ReplayGapError("requested sequence precedes retained replay buffer")
            return tuple(event for event in queue if event.sequence > sequence)

    def snapshot(self, scope: str) -> tuple[WireMessage, ...]:
        """Read current retained events without modifying acknowledgement state."""
        with self._lock:
            return tuple(self._events.get(scope, ()))
