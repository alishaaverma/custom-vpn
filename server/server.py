from __future__ import annotations

import logging
import secrets
import socket
import ssl
import threading

from config.settings import ServerSettings
from credentials.store import CredentialStore, UserRecord
from errors.exceptions import AuthorizationError, ProtocolError
from messages.constants import ACCEPT, ERROR, INCOMING, OPEN, PING, PONG, READY, REGISTER_CONTROL, REGISTERED, WAIT
from network.auth import server_authenticate
from network.protocol import recv_json, send_json
from network.relay import relay_bidirectional
from network.tls_psk import make_server_context
from server.registry import ControlSession, PendingRelay, SessionRegistry


class VPNServer:
    def __init__(self, settings: ServerSettings):
        self.settings = settings
        self.store = CredentialStore(settings.credentials_file)
        self.registry = SessionRegistry()
        self.context = make_server_context(self.store)
        self.log = logging.getLogger("vpn")
        self._stop = threading.Event()

    def serve_forever(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.settings.host, self.settings.port))
        listener.listen(128)
        listener.settimeout(1.0)
        self.log.info("Custom Python overlay server listening on %s:%s", self.settings.host, self.settings.port)

        try:
            while not self._stop.is_set():
                try:
                    raw, addr = listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self._handle_raw_connection,
                    args=(raw, addr),
                    daemon=True,
                    name=f"peer-{addr[0]}:{addr[1]}",
                ).start()
        finally:
            listener.close()

    def _handle_raw_connection(self, raw: socket.socket, addr: tuple[str, int]) -> None:
        tls: ssl.SSLSocket | None = None
        transferred = False
        try:
            tls = self.context.wrap_socket(raw, server_side=True)
            user = server_authenticate(tls, self.store)
            first = recv_json(tls)
            msg_type = first.get("type")

            if msg_type == REGISTER_CONTROL:
                transferred = self._handle_control(tls, user)
            elif msg_type == OPEN:
                transferred = self._handle_open(tls, user, first)
            elif msg_type == ACCEPT:
                transferred = self._handle_accept(tls, user, first)
            else:
                raise ProtocolError(f"Unknown initial channel type: {msg_type}")
        except Exception as exc:
            self.log.warning("Connection from %s:%s failed: %s", addr[0], addr[1], exc)
            if tls is not None:
                try:
                    send_json(tls, {"type": ERROR, "message": str(exc)})
                except Exception:
                    pass
        finally:
            if not transferred:
                try:
                    (tls or raw).close()
                except OSError:
                    pass

    def _handle_control(self, sock: socket.socket, user: UserRecord) -> bool:
        session = ControlSession(user.identity, user.virtual_ip, sock)
        if not self.registry.add_session(session):
            send_json(sock, {"type": ERROR, "message": "Identity already connected"})
            return False

        self.log.info("Control connected: %s -> %s", user.identity, user.virtual_ip)
        with session.send_lock:
            send_json(sock, {"type": REGISTERED, "virtual_ip": user.virtual_ip})

        try:
            while True:
                message = recv_json(sock)
                if message.get("type") == PING:
                    with session.send_lock:
                        send_json(sock, {"type": PONG})
                else:
                    self.log.debug("Ignoring control message from %s: %s", user.identity, message)
        except EOFError:
            pass
        finally:
            self.registry.remove_session(user.identity, sock)
            try:
                sock.close()
            except OSError:
                pass
            self.log.info("Control disconnected: %s", user.identity)
        return True

    def _handle_open(self, sock: socket.socket, user: UserRecord, message: dict) -> bool:
        target_vip = str(message.get("target_virtual_ip", ""))
        target_port = int(message.get("target_port", 0))
        target_identity = self.store.identity_for_virtual_ip(target_vip)
        if not target_identity:
            raise AuthorizationError(f"Unknown target virtual IP {target_vip}")

        target_record = self.store.get(target_identity)
        if not target_record or target_port not in target_record.allowed_ports:
            raise AuthorizationError(f"Target port {target_port} is not allowed for {target_vip}")

        target_session = self.registry.get_session(target_identity)
        if not target_session:
            raise AuthorizationError(f"Target {target_vip} is offline")

        request_id = secrets.token_hex(16)
        pending = PendingRelay(
            request_id=request_id,
            requester_identity=user.identity,
            target_identity=target_identity,
            target_port=target_port,
            origin_sock=sock,
        )
        self.registry.add_pending(pending)

        with target_session.send_lock:
            send_json(
                target_session.sock,
                {
                    "type": INCOMING,
                    "request_id": request_id,
                    "requester": user.identity,
                    "target_port": target_port,
                },
            )

        send_json(sock, {"type": WAIT, "request_id": request_id})
        self.log.info("Relay request %s: %s -> %s:%s", request_id, user.identity, target_vip, target_port)

        if not pending.event.wait(self.settings.pending_timeout_seconds):
            self.registry.pop_pending(request_id)
            send_json(sock, {"type": ERROR, "message": "Target did not accept relay in time"})
            return False

        self.registry.pop_pending(request_id)
        if pending.error or pending.target_sock is None:
            send_json(sock, {"type": ERROR, "message": pending.error or "Relay failed"})
            return False

        target_sock = pending.target_sock
        send_json(sock, {"type": READY, "request_id": request_id})
        send_json(target_sock, {"type": READY, "request_id": request_id})
        self.log.info("Relay ready %s", request_id)
        try:
            relay_bidirectional(sock, target_sock)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            try:
                target_sock.close()
            except OSError:
                pass
            self.log.info("Relay closed %s", request_id)
        return True

    def _handle_accept(self, sock: socket.socket, user: UserRecord, message: dict) -> bool:
        request_id = str(message.get("request_id", ""))
        pending = self.registry.get_pending(request_id)
        if not pending:
            send_json(sock, {"type": ERROR, "message": "Unknown or expired relay request"})
            return False
        if pending.target_identity != user.identity:
            send_json(sock, {"type": ERROR, "message": "Relay request belongs to another target"})
            return False
        if pending.target_sock is not None:
            send_json(sock, {"type": ERROR, "message": "Relay already accepted"})
            return False

        pending.target_sock = sock
        pending.event.set()
        return True
