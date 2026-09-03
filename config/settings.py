from __future__ import annotations

import json
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
class ClientSettings:
    server_host: str
    server_port: int
    identity: str
    psk_hex: str
    published_services: dict[int, PublishedService] = field(default_factory=dict)
    forwards: list[LocalForward] = field(default_factory=list)
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
        host=str(data.get("host", "0.0.0.0")),
        port=validate_port(data.get("port", 9443)),
        credentials_file=str(data["credentials_file"]),
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

    psk_hex = str(data["psk_hex"]).strip().lower()
    try:
        psk = bytes.fromhex(psk_hex)
    except ValueError as exc:
        raise ConfigurationError("psk_hex must contain hexadecimal characters only") from exc
    if len(psk) < 32:
        raise ConfigurationError("PSK must be at least 32 bytes / 256 bits")

    return ClientSettings(
        server_host=str(data["server_host"]),
        server_port=validate_port(data.get("server_port", 9443)),
        identity=str(data["identity"]),
        psk_hex=psk_hex,
        published_services=services,
        forwards=forwards,
        heartbeat_seconds=max(5, int(data.get("heartbeat_seconds", 20))),
        reconnect_seconds=max(1, int(data.get("reconnect_seconds", 3))),
        log_level=str(data.get("log_level", "INFO")),
        log_file=data.get("log_file"),
    )
