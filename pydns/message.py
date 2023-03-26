"""
DNS Message Object
"""
from typing import List
from dataclasses import dataclass, field
from typing import Type
from typing_extensions import Self

from .codec import *
from .enum import OpCode, RType, RCode
from .flags import Flags
from .answer import BaseAnswer, Answer, PreRequisite, Update
from .question import Question, Zone
from .edns import EdnsAnswer
from .exceptions import make_error

#** Variables **#
__all__ = ['Message']

#** Functions **#

def decode_list(cls, num: int, ctx: Context, raw: bytes):
    """
    deserialize a numbered list of items of the specified type
    """
    objects = []
    for _ in range(0, num):
        new = cls.decode(ctx, raw)
        objects.append(new)
    return objects

def decode_answers(cls: Type[Answer], num: int, ctx: Context, raw: bytes):
    """
    deserialize a numbered list of variable answer object types
    """
    objects = []
    for _ in range(0, num):
        # peek the header domain/rtype to determine Answer class
        idx    = ctx.index 
        peek   = PeekHeader.decode(ctx, raw)
        newcls = EdnsAnswer if peek.rtype == RType.OPT else cls
        ctx.index = idx 
        # decode answer class accordingly
        new = newcls.decode(ctx, raw)
        objects.append(new)
    return objects

#** Classes **#

@make_sequence
class PeekHeader:
    name:  Domain
    rtype: Int[16, RType, 'RType']

@make_sequence
class Header:
    id:             Int16
    flags:          Int16 
    num_questions:  Int16
    num_answers:    Int16
    num_authority:  Int16
    num_additional: Int16

@dataclass
class Message:
    id:         int
    flags:      Flags
    questions:  List[Question]   = field(default_factory=list)
    answers:    List[Answer]     = field(default_factory=list)
    authority:  List[Answer]     = field(default_factory=list)
    additional: List[BaseAnswer] = field(default_factory=list)
    
    def raise_on_error(self):
        """raise exception if message contains an error"""
        if self.flags.rcode != RCode.NoError:
            domains = list({q.name for q in self.questions})
            domains = domains[0] if len(domains) == 1 else domains
            make_error(self.flags.rcode, domains or None)

    def encode(self) -> bytes:
        """
        encode the message object into serialized bytes

        :return: serialized message bytes
        """
        ctx = Context()
        raw = bytearray()
        raw += Header(
            id=self.id, 
            flags=int(self.flags), 
            num_questions=len(self.questions), 
            num_answers=len(self.answers), 
            num_authority=len(self.authority), 
            num_additional=len(self.additional)
        ).encode(ctx)
        raw += b''.join(q.encode(ctx) for q in self.questions)
        raw += b''.join(a.encode(ctx) for a in self.answers)
        raw += b''.join(a.encode(ctx) for a in self.authority)
        raw += b''.join(a.encode(ctx) for a in self.additional)
        return bytes(raw)

    @classmethod
    def decode(cls, raw: bytes) -> Self:
        """
        decode the given raw bytes as a DNS message

        :param raw: raw bytes to decode as a DNS message
        :return:    dns message object
        """
        # parse header for message information
        ctx = Context()
        raw = bytes(raw)
        header = Header.decode(ctx, raw)
        flags  = Flags.fromint(header.flags) 
        # determine classes to parse content
        qclass, anclass, auclass = (Question, Answer, Answer) \
                if flags.op != OpCode.Update else \
                (Zone, PreRequisite, Update)
        # parse body content w/ determined classes
        questions  = decode_list(qclass, header.num_questions, ctx, raw)
        answers    = decode_answers(anclass, header.num_answers, ctx, raw)
        authority  = decode_answers(auclass, header.num_authority, ctx, raw)
        additional = decode_answers(Answer, header.num_additional, ctx, raw)
        return cls(
            id=header.id, 
            flags=flags, 
            questions=questions, 
            answers=answers, 
            authority=authority,
            additional=additional,
        )
