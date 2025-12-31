"""
Communication components of the NeoC2 framework.
"""

from .protocol_manager import ProtocolManager
from .protocols import HTTPProtocol
from .encryption import EncryptionManager

__all__ = [
    'ProtocolManager',
    'HTTPProtocol',
    'EncryptionManager'
]
