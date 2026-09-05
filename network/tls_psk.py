from __future__ import annotations

import socket
import ssl

from credentials.store import CredentialStore
def make_server_context(store: CredentialStore, cert_file: str, key_file: str) -> ssl.SSLContext:
    """Create authenticated TLS for the relay.

    Client identities are authenticated after TLS with their individual PSKs.
    Certificate TLS keeps the protocol compatible with normal Python/OpenSSL builds,
    which generally do not expose the TLS-PSK callbacks in the standard library.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def make_client_context(ca_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=ca_file)
    return context


def connect_tls(host: str, port: int, ca_file: str, timeout: float = 15.0) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(None)
    context = make_client_context(ca_file)
    try:
        return context.wrap_socket(raw, server_hostname=None)
    except Exception:
        raw.close()
        raise
