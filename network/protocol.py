from __future__ import annotations

import json
import socket
import struct
from typing import Any

from errors.exceptions import ProtocolError

MAX_FRAME = 1024 * 1024


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise EOFError("Socket closed")
        chunks.extend(part)
    return bytes(chunks)


def send_json(sock: socket.socket, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError("JSON frame too large")
    sock.sendall(struct.pack("!I", len(body)) + body)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > MAX_FRAME:
        raise ProtocolError(f"Invalid frame length: {length}")
    body = _recv_exact(sock, length)
    try:
        value = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError(f"Invalid JSON frame: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError("Protocol frame must be a JSON object")
    return value
