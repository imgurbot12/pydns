"""
EDNS OPT Answer Varient Implementation
"""
from dataclasses import dataclass
from typing_extensions import Self

from ..codec import *
from ..enum import RType
from ..answer import BaseAnswer

#** Variables **#
__all__ = ['ROOT', 'EdnsAnswer']

#: root domain (according to EDNS)
ROOT = b''

#** Classes **#

@make_sequence
class Header:
    name:           Domain
    rtype:          Int[16, RType, 'RType']
    payload_size:   Int16
    extended_rcode: Int8
    version:        Int8
    z:              Int16
    data_length:    Int16

@dataclass
class EdnsAnswer(BaseAnswer):
    name:     bytes  = ROOT
    version:  int    = 0
    content:  bytes  = b''
    udp_size: int    = 512

    @property
    def rtype(self) -> RType:
        return RType.OPT

    def encode(self, ctx: Context) -> bytes:
        return Header(
            name=self.name, 
            rtype=self.rtype, 
            payload_size=self.udp_size, 
            extended_rcode=0, 
            version=self.version, 
            z=0, 
            data_length=len(self.content)
        ).encode(ctx)

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> Self:
        header  = Header.decode(ctx, raw)
        content = ctx.slice(raw, header.data_length)
        return cls(
            name=header.name,
            version=header.version,
            udp_size=header.payload_size,
            content=content,
        )

