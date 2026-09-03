from __future__ import annotations

import logging
import socket
import threading


def _pipe(src: socket.socket, dst: socket.socket, label: str) -> None:
    log = logging.getLogger("vpn")
    try:
        while True:
            data = src.recv(64 * 1024)
            if not data:
                break
            dst.sendall(data)
    except (OSError, ConnectionError) as exc:
        log.debug("Relay pipe %s ended: %s", label, exc)
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay_bidirectional(left: socket.socket, right: socket.socket) -> None:
    a = threading.Thread(target=_pipe, args=(left, right, "left->right"), daemon=True)
    b = threading.Thread(target=_pipe, args=(right, left, "right->left"), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()
