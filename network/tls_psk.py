from __future__ import annotations

import socket
import ssl

from credentials.store import CredentialStore
from helpers.platform_info import require_supported_runtime

CIPHER_STRING = "PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256:PSK"


def make_server_context(store: CredentialStore) -> ssl.SSLContext:
    require_supported_runtime()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CIPHER_STRING)
    context.set_psk_server_callback(store.psk_for_identity, identity_hint="custom-python-vpn")
    return context


def make_client_context(identity: str, psk: bytes) -> ssl.SSLContext:
    require_supported_runtime()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CIPHER_STRING)
    context.set_psk_client_callback(lambda hint: (identity, psk))
    return context


def connect_tls(host: str, port: int, identity: str, psk: bytes, timeout: float = 15.0) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(None)
    context = make_client_context(identity, psk)
    try:
        return context.wrap_socket(raw, server_hostname=None)
    except Exception:
        raw.close()
        raise
