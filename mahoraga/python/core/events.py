from collections import defaultdict
from typing import Callable
import threading

class EventBus:
    """Simple synchronous event bus for internal Python-side communication."""

    def __init__(self):
        self._listeners: dict[str, list[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def on(self, event: str, callback: Callable):
        with self._lock:
            self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable):
        with self._lock:
            self._listeners[event] = [
                cb for cb in self._listeners[event] if cb != callback
            ]

    def emit(self, event: str, data: dict = None):
        with self._lock:
            listeners = list(self._listeners[event])
        for cb in listeners:
            try:
                cb(data or {})
            except Exception:
                pass

bus = EventBus()
