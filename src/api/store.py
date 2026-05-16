from __future__ import annotations

from collections import deque
from threading import Lock

MAX_EVENTS = 500


class EventStore:
    def __init__(self, capacity: int = MAX_EVENTS) -> None:
        self._events: deque[dict] = deque(maxlen=capacity)
        self._lock = Lock()

    def add_many(self, events: list[dict]) -> list[dict]:
        with self._lock:
            for event in events:
                self._events.appendleft(event)
            return events

    def list_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(self._events)[:limit]

    def stats(self) -> dict:
        with self._lock:
            events = list(self._events)
        total = len(events)
        benign = sum(1 for event in events if event.get("prediction") == "benign")
        malicious = total - benign
        devices = len({event.get("device_id") for event in events})
        return {
            "total": total,
            "benign": benign,
            "malicious": malicious,
            "devices": devices,
        }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
