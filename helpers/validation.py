import ipaddress


def validate_virtual_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if not ip.is_private:
        raise ValueError(f"Virtual IP must be private, got {value}")
    return str(ip)


def validate_port(value: int) -> int:
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError(f"Invalid TCP port: {value}")
    return value
