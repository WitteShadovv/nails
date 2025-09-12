"""
NAILS package initialization
"""

from .manager import NailsManager
from .exceptions import NailsError

__version__ = "1.0.0"
__all__ = ["NailsManager", "NailsError"]
