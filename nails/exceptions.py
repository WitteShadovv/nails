"""
Custom exceptions for NAILS operations
"""


class NailsError(Exception):
    """Base exception for NAILS operations"""

    pass


class NailsPermissionError(NailsError):
    """Raised when root privileges are required but not available"""

    pass


class NailsConfigError(NailsError):
    """Raised when configuration is invalid or missing"""

    pass


class NailsOverlayError(NailsError):
    """Raised when overlay filesystem operations fail"""

    pass


class NailsStateError(NailsError):
    """Raised when system is in unexpected state"""

    pass


class NailsBuildError(NailsError):
    """Raised when NixOS build/rebuild operations fail"""

    pass
