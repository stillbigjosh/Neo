"""
Communication components of the NeoC2 framework.
"""

from .protocols import HTTPProtocol
from .encryption import EncryptionManager

__all__ = [
    'HTTPProtocol',
    'EncryptionManager'
]
