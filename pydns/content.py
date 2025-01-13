"""
DNS Answer RR Content Definitions
"""
from functools import lru_cache
from typing import ClassVar, Optional, Type
from typing_extensions import Annotated, Self

from pystructs import U16, U32, Context, Domain, HintedBytes, IPv4, IPv6, Struct

from . enum import RType

#** Variables **#
__all__ = [
    'Content',
    'Unknown',

    'NULL',
    'ANY',
    'CNAME',
    'MX',
    'NS',
    'PTR',
    'SOA',
    'TXT',
    'A',
    'AAAA',
    'SRV',
]

#** Classes **#

class Content(Struct):
    rtype: ClassVar[RType]

class NULL(Content):
    rtype: ClassVar[RType] = RType.NULL

class ANY(Content):
    rtype: ClassVar[RType] = RType.ANY

class CNAME(Content):
    rtype: ClassVar[RType] = RType.CNAME
    name:  Domain

class MX(Content):
    rtype:      ClassVar[RType] = RType.MX
    preference: U16
    exchange:   Domain

class NS(Content):
    rtype:      ClassVar[RType] = RType.NS
    nameserver: Domain

class PTR(Content):
    rtype:   ClassVar[RType] = RType.PTR
    ptrname: Domain

class SOA(Content):
    rtype:     ClassVar[RType] = RType.SOA
    mname:     Domain
    rname:     Domain
    serialver: U32
    refresh:   U32
    retry:     U32
    expire:    U32
    minimum:   U32

class TXT(Content):
    rtype: ClassVar[RType] = RType.TXT
    text:  Annotated[bytes, HintedBytes(U32)]

class A(Content):
    rtype: ClassVar[RType] = RType.A
    ip:    IPv4

class AAAA(Content):
    rtype: ClassVar[RType] = RType.AAAA
    ip:    IPv6

class SRV(Content):
    rtype:    ClassVar[RType] = RType.SRV
    priority: U16
    weight:   U16
    port:     U16
    target:   Domain

class Unknown:
    """
    Mock Struct/Content Object for Unknown/Unsupported DNS Content Types
    """
    __slots__ = ('data', )

    rtype: ClassVar[RType]
    size:  ClassVar[int]

    def __init__(self, data: bytes):
        self.data = data

    def __repr__(self) -> str:
        return f'Unknown(rtype={self.rtype!r}, data=0x{self.data.hex()})'

    def pack(self, ctx: Optional[Context] = None) -> bytes:
        ctx = ctx or Context()
        return ctx.track_bytes(self.data)

    @classmethod
    def unpack(cls, raw: bytes, ctx: Optional[Context] = None) -> Self:
        ctx = ctx or Context()
        return cls(ctx.slice(raw, cls.size))

    @classmethod
    @lru_cache(maxsize=None)
    def new(cls, rtype: RType, size: int) -> Type:
        return type('Unknown', (cls, ), {'rtype': rtype, 'size': size})

#** Content **#

#: cheeky way of collecting all content types into map based on their RType
CONTENT_MAP = {v.rtype:v
    for v in globals().values()
    if isinstance(v, type) and issubclass(v, Content) and v is not Content}
