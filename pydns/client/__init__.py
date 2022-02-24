"""
various DNS client implementations for easy lookups
"""

from pydns import Question, DNSPacket

#** Variables **#
__all__ = ['UDPClient', 'HTTPSClient']

#** Classes **#

class BaseClient:
    """baseclass for client definition"""

    def query(self, *questions: Question) -> DNSPacket:
        """complete query for the given questions and return response"""
        raise NotImplementedError('baseclass must be overwritten!')

    def close(self):
        """close any resources opened by client"""
        pass

from .client import *
