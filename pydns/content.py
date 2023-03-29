"""
DNS Standard Content Sequences
"""
from typing import Optional, Type, Tuple
from typing_extensions import Self

from .codec import *
from .enum import RType

#** Variables **#
__all__ = [
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

#** Functions **#

def content(cls: Optional[type] = None, rtype: Optional[RType] = None):
    """generate content class w/ given rtype"""
    def wrapper(cls):
        cls.rtype = rtype or RType[cls.__name__] 
        return make_sequence(cls)
    return wrapper if cls is None else wrapper(cls)

#** Classes **#

class Content(Sequence):
    rtype: ClassVar[RType]

@content
class NULL(Content):
    pass

@content
class ANY(Content):
    pass

@content
class CNAME(Content):
    name: Domain

@content
class MX(Content):
    preference: Int16
    exchange:   Domain

@content
class NS(Content):
    nameserver: Domain

@content
class PTR(Content):
    ptrname: Domain

@content
class SOA(Content):
    mname:     Domain
    rname:     Domain
    serialver: Int32
    refresh:   Int32
    retry:     Int32
    expire:    Int32
    minimum:   Int32

@content
class TXT(Content):
    text: SizedBytes[32]

@content
class A(Content):
    ip: Ipv4

@content
class AAAA(Content):
    ip: Ipv6

@content
class SRV(Content):
    priority: Int16
    weight:   Int16
    port:     Int16
    target:   Domain

class Literal(Content):
    """handler for unsupported record types"""
    size: int
    
    def __class_getitem__(cls, settings: Tuple[RType, int]) -> Type[Self]:
        rtype, size = settings
        return type(f'Unknown[{rtype.name}]', (cls, ), {
            'rtype': rtype, 
            'size': size
        })

    def __init__(self, data: bytes):
        self.data = data

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.data.hex()})'

    def encode(self, ctx: Context) -> bytes:
        ctx.index += self.size
        return self.data

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> Self:
        data = ctx.slice(raw, cls.size)
        return cls(data)
