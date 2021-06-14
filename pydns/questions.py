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

    def __init__(self, name: str, qtype: Type, qclass: Class = Class.IN):
        """
        :param name:   name of the domain being looked up
        :param qtype:  question-type used to recieve specific answer type
        :param qclass: class the response will apply to
        """
        self.name   = name
        self.qtype  = qtype
        self.qclass = qclass

    def summary(self) -> str:
        """generate summary for question"""
        return f" - class={self.qclass} type={self.qtype.name} name={self.name}"

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert question object into raw-bytes"""
        return (
            ctx.domain_to_bytes(self.name)   +
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
            qtype=Type(ctx.unpack('>H', raw[:2])),
            qclass=Class(ctx.unpack('>H', raw[2:4]))
        ), idx+4
