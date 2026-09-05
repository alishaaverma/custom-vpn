from __future__ import annotations

import logging
import socket
import struct
import threading
import time

from config.settings import ClientSettings, PublishedService
from errors.handler import log_exception
from messages.constants import ACCEPT, EGRESS_OPEN, ERROR, INCOMING, PING, PONG, READY, REGISTER_CONTROL, REGISTERED
from network.auth import client_authenticate
from network.protocol import recv_json, send_json
from network.relay import relay_bidirectional
from network.tls_psk import connect_tls


class VPNClient:
    def __init__(self, settings: ClientSettings):
        self.settings = settings
        self.psk = bytes.fromhex(settings.psk_hex)
        self.log = logging.getLogger("vpn")
        self.virtual_ip: str | None = None
        self._control: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()

    def run_forever(self) -> None:
        for forward in self.settings.forwards:
            threading.Thread(
                target=self._run_forward_listener,
                args=(forward.listen_host, forward.listen_port, forward.target_virtual_ip, forward.target_port),
                daemon=True,
                name=f"forward-{forward.listen_port}",
            ).start()

        if self.settings.socks5:
            threading.Thread(
                target=self._run_socks5_listener,
                args=(self.settings.socks5.listen_host, self.settings.socks5.listen_port),
                daemon=True,
                name=f"socks5-{self.settings.socks5.listen_port}",
            ).start()

        while not self._stop.is_set():
            try:
                self._run_control_once()
            except Exception as exc:
                self.log.warning("Control connection lost: %s", exc)
            if not self._stop.is_set():
                time.sleep(self.settings.reconnect_seconds)

    def _new_authenticated_socket(self) -> socket.socket:
        sock = connect_tls(
            self.settings.server_host,
            self.settings.server_port,
            self.settings.tls_ca_file,
        )
        self.virtual_ip = client_authenticate(sock, self.settings.identity, self.psk)
        return sock

    def _run_control_once(self) -> None:
        sock = self._new_authenticated_socket()
        self._control = sock
        send_json(sock, {"type": REGISTER_CONTROL})
        registered = recv_json(sock)
        if registered.get("type") != REGISTERED:
            raise RuntimeError(registered.get("message", "Control registration failed"))
        self.virtual_ip = str(registered["virtual_ip"])
        self.log.info("Connected as %s, virtual IP %s", self.settings.identity, self.virtual_ip)

        heartbeat = threading.Thread(target=self._heartbeat_loop, args=(sock,), daemon=True, name="heartbeat")
        heartbeat.start()

        try:
            while True:
                message = recv_json(sock)
                msg_type = message.get("type")
                if msg_type == INCOMING:
                    threading.Thread(
                        target=self._handle_incoming,
                        args=(message,),
                        daemon=True,
                        name=f"incoming-{message.get('request_id', '')[:8]}",
                    ).start()
                elif msg_type == PONG:
                    pass
                elif msg_type == ERROR:
                    self.log.error("Server control error: %s", message.get("message"))
                else:
                    self.log.debug("Unhandled control message: %s", message)
        finally:
            self._control = None
            try:
                sock.close()
            except OSError:
                pass

    def _heartbeat_loop(self, sock: socket.socket) -> None:
        while self._control is sock and not self._stop.wait(self.settings.heartbeat_seconds):
            try:
                with self._send_lock:
                    send_json(sock, {"type": PING})
            except Exception:
                return

    def _handle_incoming(self, message: dict) -> None:
        request_id = str(message["request_id"])
        target_port = int(message["target_port"])
        service = self.settings.published_services.get(target_port)
        if not service:
            self.log.warning("Rejecting %s: no local published service for port %s", request_id, target_port)
            return

        local_sock: socket.socket | None = None
        tunnel_sock: socket.socket | None = None
        try:
            local_sock = socket.create_connection((service.local_host, service.local_port), timeout=10)
            local_sock.settimeout(None)
            tunnel_sock = self._new_authenticated_socket()
            send_json(tunnel_sock, {"type": ACCEPT, "request_id": request_id})
            ready = recv_json(tunnel_sock)
            if ready.get("type") != READY:
                raise RuntimeError(ready.get("message", "Relay not accepted"))
            self.log.info(
                "Serving relay %s -> %s:%s",
                request_id,
                service.local_host,
                service.local_port,
            )
            relay_bidirectional(local_sock, tunnel_sock)
        except Exception as exc:
            log_exception(f"Incoming relay {request_id} failed", exc)
        finally:
            for sock in (local_sock, tunnel_sock):
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _run_forward_listener(self, listen_host: str, listen_port: int, target_vip: str, target_port: int) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(64)
        self.log.info(
            "Local forward %s:%s -> virtual %s:%s",
            listen_host,
            listen_port,
            target_vip,
            target_port,
        )
        while not self._stop.is_set():
            local_sock, addr = listener.accept()
            threading.Thread(
                target=self._handle_local_forward,
                args=(local_sock, target_vip, target_port),
                daemon=True,
                name=f"forward-peer-{addr[0]}:{addr[1]}",
            ).start()

    def _handle_local_forward(self, local_sock: socket.socket, target_vip: str, target_port: int) -> None:
        tunnel_sock: socket.socket | None = None
        try:
            tunnel_sock = self._new_authenticated_socket()
            send_json(
                tunnel_sock,
                {
                    "type": "OPEN",
                    "target_virtual_ip": target_vip,
                    "target_port": target_port,
                },
            )
            wait = recv_json(tunnel_sock)
            if wait.get("type") == ERROR:
                raise RuntimeError(wait.get("message", "Open failed"))
            ready = recv_json(tunnel_sock)
            if ready.get("type") != READY:
                raise RuntimeError(ready.get("message", "Relay not ready"))
            relay_bidirectional(local_sock, tunnel_sock)
        except Exception as exc:
            self.log.warning("Local forward to %s:%s failed: %s", target_vip, target_port, exc)
        finally:
            try:
                local_sock.close()
            except OSError:
                pass
            if tunnel_sock:
                try:
                    tunnel_sock.close()
                except OSError:
                    pass

    def _run_socks5_listener(self, listen_host: str, listen_port: int) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(64)
        self.log.info("SOCKS5 proxy %s:%s -> encrypted server egress", listen_host, listen_port)
        while not self._stop.is_set():
            local_sock, addr = listener.accept()
            threading.Thread(
                target=self._handle_socks5_client,
                args=(local_sock,),
                daemon=True,
                name=f"socks5-peer-{addr[0]}:{addr[1]}",
            ).start()

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise EOFError("SOCKS client disconnected")
            data.extend(part)
        return bytes(data)

    @staticmethod
    def _socks_reply(sock: socket.socket, status: int) -> None:
        sock.sendall(b"\x05" + bytes((status,)) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

    def _handle_socks5_client(self, local_sock: socket.socket) -> None:
        tunnel_sock: socket.socket | None = None
        connected = False
        try:
            version, method_count = self._recv_exact(local_sock, 2)
            if version != 5:
                raise ValueError("Unsupported SOCKS version")
            methods = self._recv_exact(local_sock, method_count)
            if 0 not in methods:
                local_sock.sendall(b"\x05\xff")
                return
            local_sock.sendall(b"\x05\x00")

            version, command, reserved, address_type = self._recv_exact(local_sock, 4)
            if version != 5 or reserved != 0 or command != 1:
                self._socks_reply(local_sock, 7)
                return
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, self._recv_exact(local_sock, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._recv_exact(local_sock, 16))
            elif address_type == 3:
                length = self._recv_exact(local_sock, 1)[0]
                host = self._recv_exact(local_sock, length).decode("idna")
            else:
                self._socks_reply(local_sock, 8)
                return
            port = struct.unpack("!H", self._recv_exact(local_sock, 2))[0]

            tunnel_sock = self._new_authenticated_socket()
            send_json(tunnel_sock, {"type": EGRESS_OPEN, "host": host, "port": port})
            response = recv_json(tunnel_sock)
            if response.get("type") != READY:
                raise RuntimeError(response.get("message", "Server rejected egress request"))
            self._socks_reply(local_sock, 0)
            connected = True
            relay_bidirectional(local_sock, tunnel_sock)
        except Exception as exc:
            self.log.debug("SOCKS5 request failed: %s", exc)
            if not connected:
                try:
                    self._socks_reply(local_sock, 1)
                except OSError:
                    pass
        finally:
            try:
                local_sock.close()
            except OSError:
                pass
            if tunnel_sock:
                try:
                    tunnel_sock.close()
                except OSError:
                    pass
