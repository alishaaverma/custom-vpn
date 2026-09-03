from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from errors.exceptions import ConfigurationError
from helpers.validation import validate_port, validate_virtual_ip


@dataclass(frozen=True)
class UserRecord:
    identity: str
    psk: bytes
    virtual_ip: str
    allowed_ports: frozenset[int]
    enabled: bool = True


class CredentialStore:
    def __init__(self, path: str):
        self.path = path
        self._users = self._load(path)

    @staticmethod
    def _load(path: str) -> dict[str, UserRecord]:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            raise ConfigurationError(f"Could not load credential store {path}: {exc}") from exc

        users: dict[str, UserRecord] = {}
        seen_ips: set[str] = set()
        for item in raw.get("users", []):
            identity = str(item["identity"]).strip()
            if not identity:
                raise ConfigurationError("Credential identity cannot be empty")
            if identity in users:
                raise ConfigurationError(f"Duplicate identity: {identity}")

            try:
                psk = bytes.fromhex(str(item["psk_hex"]))
            except ValueError as exc:
                raise ConfigurationError(f"Invalid PSK hex for {identity}") from exc
            if len(psk) < 32:
                raise ConfigurationError(f"PSK for {identity} must be at least 32 bytes")

            vip = validate_virtual_ip(str(item["virtual_ip"]))
            if vip in seen_ips:
                raise ConfigurationError(f"Duplicate virtual IP: {vip}")
            seen_ips.add(vip)

            ports = frozenset(validate_port(p) for p in item.get("allowed_ports", []))
            users[identity] = UserRecord(
                identity=identity,
                psk=psk,
                virtual_ip=vip,
                allowed_ports=ports,
                enabled=bool(item.get("enabled", True)),
            )
        return users

    def get(self, identity: str) -> UserRecord | None:
        user = self._users.get(identity)
        if user and user.enabled:
            return user
        return None

    def psk_for_identity(self, identity: str | None) -> bytes:
        if not identity:
            return b""
        user = self.get(identity)
        return user.psk if user else b""

    def identity_for_virtual_ip(self, vip: str) -> str | None:
        for user in self._users.values():
            if user.enabled and user.virtual_ip == vip:
                return user.identity
        return None

    def all_users(self) -> list[UserRecord]:
        return [u for u in self._users.values() if u.enabled]
