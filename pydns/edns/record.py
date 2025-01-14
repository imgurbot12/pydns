"""
EDNS OPT Answer Varient Implementation
"""
from typing import Optional
from typing_extensions import Annotated, Self

from pyderive import dataclass
from pystructs import Context, Struct, Domain, U8, U16

from ..enum import RType
from ..answer import BaseAnswer

#** Variables **#
__all__ = ['ROOT', 'EdnsAnswer']

#: root domain (according to EDNS)
ROOT = b''

#** Classes **#

class EdnsHeader(Struct):
    name:           Domain
    rtype:          Annotated[RType, U16]
    payload_size:   U16
    extended_rcode: U8
    version:        U8
    z:              U16
    data_length:    U16

@dataclass(slots=True)
class EdnsAnswer(BaseAnswer):
    """
    EDNS Answer Object Definition
    """
    name:     bytes  = ROOT
    version:  int    = 0
    content:  bytes  = b''
    udp_size: int    = 512

    @property
    def rtype(self) -> RType:
        return RType.OPT

    def pack(self, ctx: Optional[Context] = None) -> bytes:
        ctx = ctx or Context()
        return EdnsHeader(
            name=self.name,
            rtype=self.rtype,
            payload_size=self.udp_size,
            extended_rcode=0,
            version=self.version,
            z=0,
            data_length=len(self.content)
        ).pack(ctx) + ctx.track_bytes(self.content)

    @classmethod
    def unpack(cls, raw: bytes, ctx: Optional[Context] = None) -> Self:
        ctx     = ctx or Context()
        header  = EdnsHeader.unpack(raw, ctx)
        content = ctx.slice(raw, header.data_length)
        return cls(
            name=header.name,
            version=header.version,
            udp_size=header.payload_size,
            content=content,
        )

