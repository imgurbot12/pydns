"""
"""
from typing import Tuple

from .const import *

#** Variables **#
__all__ = ['Question']

#** Classes **#

class Question:
    """
    dns-question object for serialization/deserilization

      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    def __init__(self, name: str, qtype: QType, qclass: QClass = QClass.IN):
        """
        :param name:   name of the domain being looked up
        :param qtype:  question-type used to recieve specific answer type
        :param qclass: class the response will apply to
        """
        self.name   = name
        self.qtype  = qtype
        self.qclass = qclass

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert question object into raw-bytes"""
        return (
            ctx.domain_to_bytes(self.name)  +
            ctx.pack('>H', self.qtype.value) +
            ctx.pack('>H', self.qclass.value)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> Tuple['Question', int]:
        """convert raw-bytes into question object"""
        # parse domain
        domain, idx = ctx.domain_from_bytes(raw)
        raw         = raw[idx:]
        # check for truncation of required fields
        if len(raw) < 4:
            raise PacketTruncated('packet truncated, expected 4 bytes')
        # generate class
        return cls(
            name=domain,
            qtype=QType(ctx.unpack('>H', raw[:2])),
            qclass=QClass(ctx.unpack('>H', raw[2:4]))
        ), idx+4

#TODO: remove these notes later
#NOTE:
#
# 1. iterate url w/ fmt: [chunk-len-byte] [chunk...]
# 2. for each [chunk-len-byte] check if byte startswith `11`
#     - if it does, parse fmt: ([chunk-len-byte/int-byte] [int-byte]) = uint16
#
# ex: [3] [www] [6] google [3] com [0]
# ex: [3] [www] [192] [4]              <- ([192, 4] is ptr to index 4 of bytes)
# both examples eq: `www.google.com`

#NOTE:
#
# 1. iterate url a single-byte
# 2. check if byte startswith `11`
#     - if it does, get next byte only and parse for domain from cache
#    else
#     - get n-bytes based on uint8 integer value as this chunk
# 3. keep track of how many bytes were read to keep track of indexing
#    for later ptr references
