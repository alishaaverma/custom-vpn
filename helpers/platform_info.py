import platform
import ssl
import sys


def runtime_summary() -> dict[str, str | bool]:
    return {
        "python": sys.version.split()[0],
        "os": platform.system(),
        "release": platform.release(),
        "ssl": ssl.OPENSSL_VERSION,
        "tls_psk": bool(getattr(ssl, "HAS_PSK", False)),
    }


def require_supported_runtime() -> None:
    if sys.version_info < (3, 13):
        raise RuntimeError("Python 3.13+ is required because this project uses stdlib TLS-PSK support.")
    if not getattr(ssl, "HAS_PSK", False):
        raise RuntimeError(
            "This Python/OpenSSL build does not expose TLS-PSK (ssl.HAS_PSK=False). "
            "Under the no-external-dependency requirement there is no secure fallback."
        )
