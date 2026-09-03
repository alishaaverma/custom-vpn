class VPNError(Exception):
    """Base exception for the custom overlay VPN."""


class ConfigurationError(VPNError):
    pass


class AuthenticationError(VPNError):
    pass


class ProtocolError(VPNError):
    pass


class AuthorizationError(VPNError):
    pass


class RelayError(VPNError):
    pass
