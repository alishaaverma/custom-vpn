from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from errors.exceptions import ConfigurationError
from helpers.validation import validate_port, validate_virtual_ip


@dataclass(frozen=True)
class ServerSettings:
    host: str
    port: int
    credentials_file: str
    tls_cert_file: str = "certs/server.crt"
    tls_key_file: str = "certs/server.key"
    pending_timeout_seconds: int = 15
    log_level: str = "INFO"
    log_file: str | None = None


@dataclass(frozen=True)
class PublishedService:
    port: int
    local_host: str
    local_port: int


@dataclass(frozen=True)
class LocalForward:
    listen_host: str
    listen_port: int
    target_virtual_ip: str
    target_port: int


@dataclass(frozen=True)
class Socks5Listener:
    listen_host: str
    listen_port: int


@dataclass(frozen=True)
class ClientSettings:
    server_host: str
    server_port: int
    identity: str
    psk_hex: str
    tls_ca_file: str = "certs/server.crt"
    published_services: dict[int, PublishedService] = field(default_factory=dict)
    forwards: list[LocalForward] = field(default_factory=list)
    socks5: Socks5Listener | None = None
    heartbeat_seconds: int = 20
    reconnect_seconds: int = 3
    log_level: str = "INFO"
    log_file: str | None = None


def _load_json(path: str) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigurationError(f"Could not read JSON config {path}: {exc}") from exc


def load_server_settings(path: str) -> ServerSettings:
    data = _load_json(path)
    return ServerSettings(
        host=os.getenv("VPN_SERVER_HOST", str(data.get("host", "0.0.0.0"))),
        port=validate_port(os.getenv("VPN_SERVER_PORT", data.get("port", 9443))),
        credentials_file=os.getenv("VPN_CREDENTIALS_FILE", str(data["credentials_file"])),
        tls_cert_file=os.getenv("VPN_TLS_CERT_FILE", str(data.get("tls_cert_file", "certs/server.crt"))),
        tls_key_file=os.getenv("VPN_TLS_KEY_FILE", str(data.get("tls_key_file", "certs/server.key"))),
        pending_timeout_seconds=max(3, int(data.get("pending_timeout_seconds", 15))),
        log_level=str(data.get("log_level", "INFO")),
        log_file=data.get("log_file"),
    )


def load_client_settings(path: str) -> ClientSettings:
    data = _load_json(path)
    services: dict[int, PublishedService] = {}
    for item in data.get("published_services", []):
        port = validate_port(item["virtual_port"])
        services[port] = PublishedService(
            port=port,
            local_host=str(item.get("local_host", "127.0.0.1")),
            local_port=validate_port(item.get("local_port", port)),
        )

    forwards: list[LocalForward] = []
    for item in data.get("forwards", []):
        forwards.append(
            LocalForward(
                listen_host=str(item.get("listen_host", "127.0.0.1")),
                listen_port=validate_port(item["listen_port"]),
                target_virtual_ip=validate_virtual_ip(item["target_virtual_ip"]),
                target_port=validate_port(item["target_port"]),
            )
        )

    socks5: Socks5Listener | None = None
    socks5_data = data.get("socks5")
    if socks5_data is not None:
        if not isinstance(socks5_data, dict):
            raise ConfigurationError("socks5 must be an object")
        socks5 = Socks5Listener(
            listen_host=str(socks5_data.get("listen_host", "127.0.0.1")),
            listen_port=validate_port(socks5_data["listen_port"]),
        )

    psk_hex = os.getenv("VPN_CLIENT_PSK_HEX", str(data["psk_hex"])).strip().lower()
    try:
        psk = bytes.fromhex(psk_hex)
    except ValueError as exc:
        raise ConfigurationError("psk_hex must contain hexadecimal characters only") from exc
    if len(psk) < 32:
        raise ConfigurationError("PSK must be at least 32 bytes / 256 bits")

    return ClientSettings(
        server_host=os.getenv("VPN_CLIENT_SERVER_HOST", str(data["server_host"])),
        server_port=validate_port(os.getenv("VPN_CLIENT_SERVER_PORT", data.get("server_port", 9443))),
        identity=os.getenv("VPN_CLIENT_IDENTITY", str(data["identity"])),
        psk_hex=psk_hex,
        tls_ca_file=os.getenv("VPN_TLS_CA_FILE", str(data.get("tls_ca_file", "certs/server.crt"))),
        published_services=services,
        forwards=forwards,
        socks5=socks5,
        heartbeat_seconds=max(5, int(data.get("heartbeat_seconds", 20))),
        reconnect_seconds=max(1, int(data.get("reconnect_seconds", 3))),
        log_level=str(data.get("log_level", "INFO")),
        log_file=data.get("log_file"),
    )
