from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field


@dataclass
class ControlSession:
    identity: str
    virtual_ip: str
    sock: socket.socket
    send_lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class PendingRelay:
    request_id: str
    requester_identity: str
    target_identity: str
    target_port: int
    origin_sock: socket.socket
    event: threading.Event = field(default_factory=threading.Event)
    target_sock: socket.socket | None = None
    error: str | None = None


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ControlSession] = {}
        self._pending: dict[str, PendingRelay] = {}
        self._lock = threading.RLock()

    def add_session(self, session: ControlSession) -> bool:
        with self._lock:
            if session.identity in self._sessions:
                return False
            self._sessions[session.identity] = session
            return True

    def remove_session(self, identity: str, sock: socket.socket) -> None:
        with self._lock:
            current = self._sessions.get(identity)
            if current and current.sock is sock:
                self._sessions.pop(identity, None)

    def get_session(self, identity: str) -> ControlSession | None:
        with self._lock:
            return self._sessions.get(identity)

    def add_pending(self, pending: PendingRelay) -> None:
        with self._lock:
            self._pending[pending.request_id] = pending

    def get_pending(self, request_id: str) -> PendingRelay | None:
        with self._lock:
            return self._pending.get(request_id)

    def pop_pending(self, request_id: str) -> PendingRelay | None:
        with self._lock:
            return self._pending.pop(request_id, None)
