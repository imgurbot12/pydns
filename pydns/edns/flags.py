"""
"""
from ..const import *
from ..flags import Flags

#** Variables **#
__all__ = ['EDNSFlags']

#** Classes **#

class EDNSFlags(Flags):
    """"""

    def __init__(self, do: bool = False):
        self.do = do

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert EDNSFlags to raw-bytes"""
        return bytes([self.do << 7, 0])

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'EDNSFlags':
        """convert raw-bytes to EDNSFlags"""
        ctx._idx += 2
        byte1 = raw[0]
        return cls(do=(byte1 & 0b10000000) > 0)
