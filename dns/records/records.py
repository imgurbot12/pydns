"""
"""
import struct
from typing import Tuple

from ..const import *
from . import content

#** Variables **#
__all__ = ['ResourceRecord']

_content_classes = {
    attr:getattr(content, attr)
    for attr in content.__all__
    if attr != 'RecordContent'
}

#** Classes **#

class ResourceRecord:
    """a complete RR used as a response to a given question"""

    def __init__(self,
        name:    str,
        ttl:     int,
        content: content.RecordContent,
        rclass:  Class = Class.IN,
    ):
        """
        :param name:    name of domain the question is in response to
        :param ttl:     how long the response is valid for
        :param content: resource-record content object
        :param rclass:  class the record is related to
        """
        self.name    = name
        self.rclass  = rclass
        self.ttl     = ttl
        self.content = content

    @property
    def rtype(self):
        return self.content.const

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert resource-record into raw-bytes"""
        validate_int('ttl', self.ttl, 32)
        base = (
            ctx.domain_to_bytes(self.name)    +
            ctx.pack('>H', self.rtype.value)  +
            ctx.pack('>H', self.rclass.value) +
            ctx.pack('>I', self.ttl)
        )
        ctx._idx += 2 #pre-increment index location, due to data-length pos
        content = self.content.to_bytes(ctx)
        return (base + struct.pack('>H', len(content)) + content)

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> Tuple['ResourceRecord', int]:
        """convert raw-bytes into resource-record object"""
        # parse domain and separate flags from rest of bytes
        domain, idx  = ctx.domain_from_bytes(raw)
        (flags, raw) = (raw[idx:idx+8], raw[idx+8:])
        if len(flags) != 8:
            raise PacketTruncated('record flags truncated')
        # attempt to retrieve data using data-length
        (dlen, raw) = (ctx.unpack('>H', raw[:2]), raw[2:])
        (data, raw) = (raw[:dlen], raw[dlen:])
        if len(data) < dlen:
            raise PacketTruncated('too little data for data-len: %d' % dlen)
        # parse flags in order to handle SerialCtx.index increment
        rtype   = Type(ctx.unpack('>H', flags[:2]))
        rclass  = Class(ctx.unpack('>H', flags[2:4]))
        ttl     = ctx.unpack('>I', flags[4:])
        # finally parse content using the right object based on RType
        content = _content_classes[rtype.name].from_bytes(data, ctx)
        # generate new object
        return (
            cls(name=domain, rclass=rclass, ttl=ttl, content=content),
            idx + 10 + dlen
        )
