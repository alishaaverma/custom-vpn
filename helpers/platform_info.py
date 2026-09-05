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
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10+ is required for this project.")
