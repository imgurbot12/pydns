"""
DNS Answer Record Instance/Format
"""
from typing import Optional, Type
from abc import abstractmethod
from dataclasses import dataclass
from typing import Protocol
from typing_extensions import Self

from .codec import *
from .content import Content, Literal
from .enum import RType, RClass
from . import content

#** Variables **#
__all__ = ['BaseAnswer', 'Answer', 'PreRequisite', 'Update']

#: all objects exported by content
CONTENT_ALL = [getattr(content, name) for name in content.__all__]

#: map of content-types mapped to content objects
CONTENT_MAP = {r.rtype:r for r in CONTENT_ALL if issubclass(r, Content)}

#** Functions **#

def get_rclass(rtype: RType, size: Optional[int] = None) -> Type[Content]:
    """retrieve record content class based on record-type"""
    # get working content class if rtype is supported
    if rtype in CONTENT_MAP:
        return CONTENT_MAP[rtype]
    # else just encapsulate in sized-bytes object
    if size is not None:
        return Literal[rtype, size]
    raise ValueError(f'unsupported rtype: {rtype.name!r}')

#** Classes **#

@make_sequence
class Header:
    name:   Domain
    rtype:  Int[16, RType, 'RType']
    rclass: Int[16, RClass, 'RClass']
    ttl:    Int32

class BaseAnswer(Protocol):
    """Baseclass for defining `Answer` objects"""
    name: bytes
    
    @property
    @abstractmethod
    def rtype(self) -> RType:
        raise NotImplementedError

    @abstractmethod
    def encode(self, ctx: Context) -> bytes:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def decode(cls, ctx: Context, raw: bytes) -> Self:
        raise NotImplementedError

@dataclass
class Answer(BaseAnswer):
    """Standard DNS Answer Implementation"""
    name:    bytes
    ttl:     int
    content: Content
    rclass:  RClass  = RClass.IN
    
    @property
    def rtype(self) -> RType:
        return self.content.rtype

    def encode(self, ctx: Context) -> bytes:
        head = Header(self.name, self.rtype, self.rclass, self.ttl).encode(ctx)
        ctx.index += 2 # pre-increment index since body-size goes before content
        body = self.content.encode(ctx)
        size = len(body).to_bytes(2, 'big')
        return head + size + body

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> Self:
        # parse header and size of body
        header = Header.decode(ctx, raw)
        size   = Int16.decode(ctx, raw)
        # determine content-type based on rtype in header
        rclass  = get_rclass(header.rtype, size)
        content = rclass.decode(ctx, raw)
        return cls(header.name, header.ttl, content, header.rclass)

@dataclass
class PreRequisite(Answer):
    """Alias for Answer in UPDATE action DNS Requests with Sensible Defaults"""
    ttl:     int = 0
    content: Content = field(default_factory=content.ANY)

class Update(Answer):
    """Alias of Answer in UPDATE action DNS Requests"""
    pass
