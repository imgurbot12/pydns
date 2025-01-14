"""
DNS Flags Implementation
"""
from enum import IntFlag
from typing_extensions import Self

from pyderive import dataclass

from .enum import QR, OpCode, RCode

#** Variables **#
__all__ = ['Flags']

#** Functions **#

def unmask(flags: int, start: int, end: int) -> int:
    """
    unmask a range of bits from the given integer
    """
    m1   = (1 << end) - 1
    m2   = (1 << start) - 1
    mask = m1 ^ m2
    return flags & mask

#** Classes **#

class Flag(IntFlag):
    Authorative      = 1 << 10
    Truncated        = 1 << 9
    RDesired         = 1 << 8
    RAvailable       = 1 << 7
    Authenticated    = 1 << 5
    CheckingDisabled = 1 << 4

@dataclass(slots=True)
class Flags:
    """
    DNS BitFlags Object Definition
    """
    qr:                   QR
    op:                   OpCode
    authorative:          bool  = False
    truncated:            bool  = False
    recursion_desired:    bool  = True
    recursion_available:  bool  = False
    answer_authenticated: bool  = False
    checking_disabled:    bool  = False
    rcode:                RCode = RCode.NoError

    def __int__(self) -> int:
        flags  = self.qr << 15
        flags |= self.op << 11
        flags |= Flag.Authorative if self.authorative else 0
        flags |= Flag.Truncated if self.truncated else 0
        flags |= Flag.RDesired if self.recursion_desired else 0
        flags |= Flag.RAvailable if self.recursion_available else 0
        flags |= Flag.Authenticated if self.answer_authenticated else 0
        flags |= Flag.CheckingDisabled if self.checking_disabled else 0
        flags |= self.rcode
        return int(flags)

    @classmethod
    def fromint(cls, i: int) -> Self:
        return cls(
            qr=QR(i >> 15),
            op=OpCode(unmask(i, 11, 15)),
            authorative=bool(i & Flag.Authorative),
            truncated=bool(i & Flag.Truncated),
            recursion_desired=bool(i & Flag.RDesired),
            recursion_available=bool(i & Flag.RAvailable),
            answer_authenticated=bool(i & Flag.Authenticated),
            checking_disabled=bool(i & Flag.CheckingDisabled),
            rcode=RCode(unmask(i, 0, 4)),
        )
