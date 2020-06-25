"""
"""
from typing import List, Optional, Tuple

from .const import *
from .flags import Flags
from .questions import Question
from .records import ResourceRecord
from .edns import EDNSResourceRecord


#** Variables **#
__all__ = ['TranactionID', 'DNSPacket']

TranactionID = int

#** Functions **#

#TODO: dns library needs to support EDNS for things like dig

#** Classes **#
class DNSPacket:

    def __init__(self,
        id:         TranactionID,
        flags:      Flags,
        questions:  List[Question],
        answers:    Optional[List[ResourceRecord]] = None,
        authority:  Optional[List[ResourceRecord]] = None,
        additional: Optional[List[ResourceRecord]] = None,
    ):
        self.id        = id
        self.flags     = flags
        self.questions = questions
        self.answers   = answers or []
        self.authority = authority or []
        self.additonal = additional or []

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert dns-packet into raw-bytes"""
        validate_int('id', self.id, 16)
        return (
            ctx.pack('>H', self.id)             +
            self.flags.to_bytes(ctx)            +
            ctx.pack('>H', len(self.questions)) +
            ctx.pack('>H', len(self.answers))   +
            ctx.pack('>H', len(self.authority)) +
            ctx.pack('>H', len(self.additonal)) +
            b''.join(q.to_bytes(ctx) for q in self.questions) +
            b''.join(a.to_bytes(ctx) for a in self.answers)   +
            b''.join(a.to_bytes(ctx) for a in self.authority) +
            b''.join(a.to_bytes(ctx) for a in self.additonal)
        )

    @staticmethod
    def _obj_from_bytes(obj: object, num: int,
        raw: bytes,  ctx: SerialCtx) -> Tuple[List[object], bytes]:
        """convert raw-bytes into list of objects"""
        objects = []
        for _ in range(num):
            item, idx = obj.from_bytes(raw, ctx)
            raw       = raw[idx:]
            objects.append(item)
        return (objects, raw)

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'DNSPacket':
        """convert raw-bytes into dns-packet"""
        id    = ctx.unpack('>H', raw[:2])
        flags = Flags.from_bytes(raw[2:4], ctx)
        nq    = ctx.unpack('>H', raw[4:6])
        nan   = ctx.unpack('>H', raw[6:8])
        nau   = ctx.unpack('>H', raw[8:10])
        nad   = ctx.unpack('>H', raw[10:12])
        raw   = raw[12:]
        question,  raw = cls._obj_from_bytes(Question, nq, raw, ctx)
        answer,    raw = cls._obj_from_bytes(ResourceRecord, nan, raw, ctx)
        authority, raw = cls._obj_from_bytes(ResourceRecord, nau, raw, ctx)
        additonal, raw = cls._obj_from_bytes(EDNSResourceRecord, nad, raw, ctx)
        return cls(
            id=id,
            flags=flags,
            questions=question,
            answers=answer,
            authority=authority,
            additional=additonal,
        )
