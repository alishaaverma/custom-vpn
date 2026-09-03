from __future__ import annotations

import hashlib
import hmac
import secrets
import socket

from credentials.store import CredentialStore, UserRecord
from errors.exceptions import AuthenticationError
from messages.constants import AUTH_CHALLENGE, AUTH_FAILED, AUTH_OK, AUTH_RESPONSE
from network.protocol import recv_json, send_json


def _proof(psk: bytes, nonce_hex: str, identity: str) -> str:
    message = bytes.fromhex(nonce_hex) + identity.encode("utf-8")
    return hmac.new(psk, message, hashlib.sha256).hexdigest()


def server_authenticate(sock: socket.socket, store: CredentialStore) -> UserRecord:
    nonce = secrets.token_hex(32)
    send_json(sock, {"type": AUTH_CHALLENGE, "nonce": nonce})
    response = recv_json(sock)
    if response.get("type") != AUTH_RESPONSE:
        raise AuthenticationError("Expected authentication response")

    identity = str(response.get("identity", ""))
    user = store.get(identity)
    if not user:
        send_json(sock, {"type": AUTH_FAILED, "message": "Unknown or disabled identity"})
        raise AuthenticationError("Unknown or disabled identity")

    expected = _proof(user.psk, nonce, identity)
    supplied = str(response.get("proof", ""))
    if not hmac.compare_digest(expected, supplied):
        send_json(sock, {"type": AUTH_FAILED, "message": "Authentication failed"})
        raise AuthenticationError("Invalid proof")

    send_json(sock, {"type": AUTH_OK, "virtual_ip": user.virtual_ip})
    return user


def client_authenticate(sock: socket.socket, identity: str, psk: bytes) -> str:
    challenge = recv_json(sock)
    if challenge.get("type") != AUTH_CHALLENGE:
        raise AuthenticationError("Expected authentication challenge")
    nonce = str(challenge["nonce"])
    send_json(
        sock,
        {
            "type": AUTH_RESPONSE,
            "identity": identity,
            "proof": _proof(psk, nonce, identity),
        },
    )
    result = recv_json(sock)
    if result.get("type") != AUTH_OK:
        raise AuthenticationError(str(result.get("message", "Authentication failed")))
    return str(result["virtual_ip"])
