from ..const import SerialCtx, Type
from ..records import RecordContent

#** Variables **#
__all__ = ['ANY']

#** Classes **#

class ANY(RecordContent):
    """content type used in pre-requisite to declare any RR is acceptable"""
    const = Type.ANY

    def __init__(self):
        pass

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        return b''

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'NONE':
        return cls()
