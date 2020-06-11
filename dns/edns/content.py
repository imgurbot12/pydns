"""
"""
from typing import Optional

from ..const import *

#** Variables **#
__all__ = [
    'EDNSRecordContent',

    'Cookie'
]

#** Classes **#

class EDNSRecordContent:
    """baseclass for content included in EDNSResourceRecord"""
    const = None

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        raise NotImplementedError('must be overwritten!')

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'EDNSRecordContent':
        raise NotImplementedError('must be overwritten!')

class Cookie(EDNSRecordContent):
    const = EDNSOption.Cookie

    def __init__(self, client: bytes, server: Optional[bytes] = None):
        """
        :param client: client cookie initially sent by client
        :param server: server cookie sent back by server
        """
        self.client_cookie = client
        self.server_cookie = server

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert cookie-option into raw-bytes"""
        if len(self.client_cookie) != 8:
            raise ValueError('client cookie must be 8bytes long')
        return (self.client_cookie + (self.server_cookie or b''))

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'Cookie':
        """convert raw-bytes into cookie-option"""
        (client, server) = (raw[:8], raw[8:])
        return cls(client, server or None)
