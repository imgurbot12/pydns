"""
DNS Answer Object Definitions
"""
from abc import abstractmethod
from typing import Optional, Protocol, Type
from typing_extensions import Annotated, Self

from pyderive import dataclass, field
from pystructs import U16, U32, Context, Domain, Struct

from .enum import RType, RClass
from .content import ANY, CONTENT_MAP, Content, Unknown

#** Variables **#
__all__ = ['BaseAnswer', 'Answer', 'PreRequisite', 'Update']

#** Functions **#

def get_ctype(rtype: RType, size: Optional[int] = None) -> Type[Content]:
    """
    retrieve record content type based on record-type (and size if specified)

    :param rtype: record-type of requested object type
    :param size:  optional size-hint for record-type
    :return:      content record type
    """
    if rtype in CONTENT_MAP:
        return CONTENT_MAP[rtype]
    if size is not None:
        return Unknown.new(rtype, size)
    raise ValueError(f'Unsupported RR Type: {rtype.name!r}')

def peek_rtype(raw: bytes, ctx: Context) -> RType:
    """
    peek next anwser in buffer to retrieve specified RR Type
    """
    idx  = ctx.index
    peek = PeekHeader.unpack(raw, ctx)
    ctx.index = idx
    return peek.rtype

#** Classes **#

#NOTE: The nature of dns domain name compression prevents
# the simple implementation of including the content-size
# and content-body within `AnswerHeader` with something like
# a `HintedBytes(U16)` instance which would require recursively
# packing/unpacking the content assigned to a bytearray.

class PeekHeader(Struct):
    name:  Domain
    rtype: Annotated[RType, U16]

class AnswerHeader(PeekHeader):
    rclass:  Annotated[RClass, U16]
    ttl:     U32

class BaseAnswer(Protocol):
    """
    Baseclass for defining `Answer` objects
    """
    name: bytes

    @property
    @abstractmethod
    def rtype(self) -> RType:
        raise NotImplementedError

    @abstractmethod
    def pack(self, ctx: Optional[Context] = None) -> bytes:
        """
        pack answer object into serialized bytes

        :param ctx: serialization context object
        :return:    serialized bytes
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def unpack(cls, raw: bytes, ctx: Optional[Context] = None) -> Self:
        """
        unpack serialized bytes into deserialized answer object

        :param raw: raw byte buffer
        :param ctx: deserialization context object
        :return:    unpacked answer object
        """
        raise NotImplementedError

@dataclass(slots=True)
class Answer(BaseAnswer):
    """
    Standard DNS Answer Implementation
    """
    name:    bytes
    ttl:     int
    content: Content
    rclass:  RClass = RClass.IN

    @property
    def rtype(self) -> RType:
        return self.content.rtype

    def pack(self, ctx: Optional[Context] = None) -> bytes:
        ctx  = ctx or Context()
        head = AnswerHeader(name=self.name, rtype=self.content.rtype,
            rclass=self.rclass, ttl=self.ttl).pack(ctx)
        ctx.index += 2 # pre-increment index (placeholder for size)
        body = self.content.pack(ctx)
        size = len(body).to_bytes(2, 'big')
        return head + size + body

    @classmethod
    def unpack(cls, raw: bytes, ctx: Optional[Context] = None) -> Self:
        ctx     = ctx or Context()
        header  = AnswerHeader.unpack(raw, ctx)
        size    = int.from_bytes(ctx.slice(raw, 2), 'big')
        ctype   = get_ctype(header.rtype, size)
        content = ctype.unpack(raw, ctx)
        return cls(header.name, header.ttl, content, header.rclass)

@dataclass(slots=True)
class PreRequisite(Answer):
    """
    Alias for Answer in UPDATE action DNS Requests with Sensible Defaults
    """
    ttl:     int = 0
    content: Content = field(default=ANY)

class Update(Answer):
    """
    Alias for Answer in UPDATE action DNS Requests
    """
    pass
