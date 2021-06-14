"""
"""
import struct
from typing import Optional, Tuple

from ..const import *
from . import content
from .flags import EDNSFlags
from ..records import ResourceRecord

#** Variables **#
__all__ = ['EDNSResourceRecord']

_default_flags = EDNSFlags(do=False)

_content_classes = {
    attr:getattr(content, attr)
    for attr in content.__all__
    if attr != 'EDNSRecordContent'
}

#TODO: it is possible that more than one option can be added to an EDNS
# record, right now the current implementation assumes there is only one
# but parsing may need to change in the future

#** Classes **#

class EDNSResourceRecord(ResourceRecord):
    """"""

    def __init__(self,
        size:    int       = 512,
        rcode:   int       = 0,
        version: int       = 0,
        flags:   EDNSFlags = _default_flags,
        content: Optional[content.RecordContent] = None,
    ):
        self.udp_size = size
        self.rcode    = rcode
        self.version  = version
        self.flags    = flags
        self.content  = content

    def summary(self) -> str:
        """generate summary for edns-resource-record"""
        (cname, content) = ('Empty', '')
        if self.content is not None:
            cname   = self.content.__class__.__name__
            content = self.content.summary()
        return \
            f"  - type=OPT name=<root> size={self.udp_size} code={self.rcode} version={self.version}\n" \
            f"    flags:\n      {self.flags.summary()}\n" \
            f"    content ({cname}):\n      {content}"

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert EDNSResourceRecord to raw-bytes"""
        validate_int('udp_size', self.udp_size, bits=16)
        validate_int('rcode', self.rcode, bits=8)
        validate_int('version', self.version, bits=8)
        base = (
            bytes([0, 0, 41])                 +
            ctx.pack('>H', self.udp_size)     +
            bytes([self.rcode, self.version]) +
            self.flags.to_bytes(ctx)
        )
        ctx._idx += 5 # 2 bytes from content-length and 3 from domain + OPT(41)
        content = b''
        if self.content:
            ctx._idx += 4 # pre-increment index before converting data to bytes
            data     = self.content.to_bytes(ctx)
            content += struct.pack('>H', self.content.const.value)
            content += struct.pack('>H', len(data)) + data
        return (base + struct.pack('>H', len(content)) + content)

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> Tuple['EDNSResourceRecord', int]:
        """convert raw-bytes into new EDNSResourceRecord"""
        ctx._idx += 3 # skip prefix of <root> & OPT rcode
        udp_size = ctx.unpack('>H', raw[3:5])
        rcode    = raw[6]
        version  = raw[7]
        flags    = EDNSFlags.from_bytes(raw[7:9], ctx)
        datalen  = ctx.unpack('>H', raw[9:11])
        # parse content if there is any
        content  = None
        if datalen:
            data    = raw[11:]
            otype   = EDNSOption(ctx.unpack('>H', data[:2]))
            olen    = ctx.unpack('>H', data[2:4]) + 4
            content = _content_classes[otype.name].from_bytes(data[4:olen], ctx)
        return (
            cls(udp_size, rcode, version, flags, content),
            11 + datalen
        )
