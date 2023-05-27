"""
DNS Standard Content Sequences
"""
from typing import Optional, Type, Tuple, ClassVar
from typing_extensions import Annotated, Self, dataclass_transform

from pystructs import *

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

@dataclass_transform()
def content(
    cls:     Optional[type] = None, 
    rtype:   Optional[RType] = None,
    **kwargs
):
    """generate content class w/ given rtype"""
    def wrapper(cls):
        cls.rtype = rtype or RType[cls.__name__]
        return compile(cls, **kwargs)
    return wrapper if cls is None else wrapper(cls) #type: ignore

#** Classes **#

class Content(Struct):
    rtype: ClassVar[RType]

@content
class NULL(Content):
    pass

@content
class ANY(Content):
    pass

@content(slots=True)
class CNAME(Content):
    name: Domain

@content(slots=True)
class MX(Content):
    preference: U16
    exchange:   Domain

@content(slots=True)
class NS(Content):
    nameserver: Domain

@content(slots=True)
class PTR(Content):
    ptrname: Domain

@content(slots=True)
class SOA(Content):
    mname:     Domain
    rname:     Domain
    serialver: U32
    refresh:   U32
    retry:     U32
    expire:    U32
    minimum:   U32

@content(slots=True)
class TXT(Content):
    text: Annotated[bytes, SizedBytes[U32]]

@content(slots=True)
class A(Content):
    ip: IPv4

@content(slots=True)
class AAAA(Content):
    ip: IPv6

@content(slots=True)
class SRV(Content):
    priority: U16
    weight:   U16
    port:     U16
    target:   Domain

class Literal(Content):
    """handler for unsupported record types"""
    rtype: RType
    size:  int
 
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
