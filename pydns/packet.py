"""
"""
from typing import List, Optional, Tuple

# primary dns implementation
from .const import *
from .flags import Flags
from .questions import Question
from .records import ResourceRecord
from .exceptions import get_exception_by_code
# ddns extensions
from .ddns import Zone, PreRequisite, Update
# edns extensions
from .edns import EDNSResourceRecord


#** Variables **#
__all__ = ['TranactionID', 'DNSPacket']

TranactionID = int

#** Classes **#

class DNSPacket:
    """domain name server packet object for reading/writing data"""

    def __init__(self,
        id:         TranactionID,
        flags:      Flags,
        questions:  Optional[List[Question]]       = None,
        answers:    Optional[List[ResourceRecord]] = None,
        authority:  Optional[List[ResourceRecord]] = None,
        additional: Optional[List[ResourceRecord]] = None,
        zones:      Optional[List[Zone]]           = None,
        requisites: Optional[List[PreRequisite]]   = None,
        updates:    Optional[List[Update]]         = None,
    ):
        """
        :param id:         transaction id used to track the a req/resp pair
        :param flags:      booleans related to requested/available dns behaviors
        :param questions:  records the client wants to retrieve
        :param answers:    responses to given questions if any
        :param authority:  additional responses pretaining to authority
        :param additional:  additional miscellaneous responses
        :param zones:      (DDNS) related zones for updates (replaces questions)
        :param requisites: (DDNS) required RRs for updates (replaces answers)
        :param updates:    (DDNS) new/modified RRs (replaces authority)
        """
        self.id        = id
        self.flags     = flags
        self.questions = questions or zones
        self.answers   = answers or requisites or []
        self.authority = authority or updates or []
        self.additional = additional or []

    def raise_on_error(self):
        """raise exception if opcode is a server-failure"""
        if self.flags.rcode != RCode.NoError:
            raise get_exception_by_code(self.flags.rcode)

    @property
    def zones(self) -> List[Zone]:
        """alias for questions used as part of DDNS"""
        return self.questions

    @property
    def requisites(self) -> List[PreRequisite]:
        """alias for answers used as part of DDNS"""
        return self.answers

    @property
    def updates(self) -> List[Update]:
        """alias for updates used as part of DDNS"""
        return self.authority

    def summary(self) -> str:
        """generate summary for DNSPacket"""
        flags = self.flags.summary()
        questions = '\n'.join(q.summary() for q in self.questions)
        # collect answers
        answers = '\n'.join(a.summary() for a in self.answers)
        authority = '\n'.join(a.summary() for a in self.authority)
        additional = '\n'.join(a.summary() for a in self.additional)
        # add newline prefix if any answers present
        answers = ('\n' + answers) if answers else ''
        authority = ('\n' + authority) if authority else ''
        additional = ('\n' + additional) if additional else ''

        return \
            f"=== DNS PACKET ===\nFlags:\n{flags}\nQuestions:\n{questions}\n" \
            f"Answers:{answers}\nAuthority:{authority}\nAdditional:{additional}"

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert dns-packet into raw-bytes"""
        validate_int('id', self.id, 16)
        return (
            ctx.pack('>H', self.id)             +
            self.flags.to_bytes(ctx)            +
            ctx.pack('>H', len(self.questions)) +
            ctx.pack('>H', len(self.answers))   +
            ctx.pack('>H', len(self.authority)) +
            ctx.pack('>H', len(self.additional)) +
            b''.join(q.to_bytes(ctx) for q in self.questions) +
            b''.join(a.to_bytes(ctx) for a in self.answers)   +
            b''.join(a.to_bytes(ctx) for a in self.authority) +
            b''.join(a.to_bytes(ctx) for a in self.additional)
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
        if flags.op == OpCode.Update:
            question,  raw = cls._obj_from_bytes(Zone, nq, raw, ctx)
            answer,    raw = cls._obj_from_bytes(PreRequisite, nan, raw, ctx)
            authority, raw = cls._obj_from_bytes(Update, nau, raw, ctx)
        else:
            question,  raw = cls._obj_from_bytes(Question, nq, raw, ctx)
            answer,    raw = cls._obj_from_bytes(ResourceRecord, nan, raw, ctx)
            authority, raw = cls._obj_from_bytes(ResourceRecord, nau, raw, ctx)
        additional, raw = cls._obj_from_bytes(EDNSResourceRecord, nad, raw, ctx)
        return cls(
            id=id,
            flags=flags,
            questions=question,
            answers=answer,
            authority=authority,
            additional=additional,
        )
