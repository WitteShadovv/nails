"""
NAILS package initialization
"""

from .exceptions import NailsError
from .manager import NailsManager

__version__ = "1.0.0"
__all__ = ["NailsManager", "NailsError"]
