"""
DNS Message Object Definition
"""
from typing import List, Optional
from typing_extensions import Self

from pyderive import dataclass, field
from pystructs import U16, Context, Struct

from .answer import Answer, BaseAnswer, PreRequisite, Update, peek_rtype
from .edns import EdnsAnswer
from .enum import OpCode, RCode, RType
from .exceptions import raise_error
from .flags import Flags
from .question import Question, Zone

#** Variables **#
__all__ = ['Message']

#** Classes **#

class PacketHeader(Struct):
    id:         U16
    flags:      U16
    questions:  U16
    answers:    U16
    authority:  U16
    additional: U16

@dataclass(slots=True)
class Message:
    """
    DNS Message Object Definition (Request & Response Packet)
    """
    id:         int
    flags:      Flags
    questions:  List[Question]   = field(default_factory=list)
    answers:    List[Answer]     = field(default_factory=list)
    authority:  List[Answer]     = field(default_factory=list)
    additional: List[BaseAnswer] = field(default_factory=list)

    def raise_on_error(self):
        """
        raise exception if message contains an error
        """
        if self.flags.rcode != RCode.NoError:
            domains = list({q.name for q in self.questions})
            domains = domains[0] if len(domains) == 1 else domains
            raise_error(self.flags.rcode, domains or None)

    def pack(self, ctx: Optional[Context] = None) -> bytes:
        """
        pack message object into serialized bytes

        :param ctx: serialization context object
        :return:    serialized bytes
        """
        ctx  = ctx or Context()
        raw  = bytearray()
        raw += PacketHeader(
            id=self.id,
            flags=int(self.flags),
            questions=len(self.questions),
            answers=len(self.answers),
            authority=len(self.authority),
            additional=len(self.additional),
        ).pack(ctx)
        raw += b''.join(q.pack(ctx) for q in self.questions)
        raw += b''.join(a.pack(ctx) for a in self.answers)
        raw += b''.join(a.pack(ctx) for a in self.authority)
        raw += b''.join(a.pack(ctx) for a in self.additional)
        return bytes(raw)

    @classmethod
    def unpack(cls, raw: bytes, ctx: Optional[Context] = None) -> Self:
        """
        unpack serialized bytes into deserialized message object

        :param raw: raw byte buffer
        :param ctx: deserialization context object
        :return:    unpacked message object
        """
        ctx   = ctx or Context()
        head  = PacketHeader.unpack(raw, ctx)
        flags = Flags.fromint(head.flags)
        # determine classes to parse content
        qclass, anclass, auclass = (Question, Answer, Answer) \
            if flags.op != OpCode.Update else \
            (Zone, PreRequisite, Update)
        # parse body content w/ determined classes
        questions  = [qclass.unpack(raw, ctx) for _ in range(head.questions)]
        answers    = [anclass.unpack(raw, ctx) for _ in range(head.answers)]
        authority  = [auclass.unpack(raw, ctx) for _ in range(head.authority)]
        additional = []
        for _ in range(head.additional):
            rtype  = peek_rtype(raw, ctx)
            newcls = EdnsAnswer if rtype == RType.OPT else cls
            answer = newcls.unpack(raw, ctx)
            additional.append(answer)
        return cls(
            id=head.id,
            flags=flags,
            questions=questions,
            answers=answers,
            authority=authority,
            additional=additional
        )
