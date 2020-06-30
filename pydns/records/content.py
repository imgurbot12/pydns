import ipaddress
from typing import Union

from ..const import *

#** Variables **#
__all__ = [
    'RecordContent',

    'CNAME',
    'MX',
    'NS',
    'PTR',
    'SOA',
    'TXT',
    'A',
    'AAAA'
]

#** Classes **#

class RecordContent:
    """baseclass for content being applied to a ResourceRecord object"""
    const = None

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        raise NotImplementedError('must be overwritten!')

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'RecordContent':
        raise NotImplementedError('must be overwritten!')

class _DomainRecordContent(RecordContent):
    _key = ''

    def __init__(self, domain: str):
        setattr(self, self._key, domain)

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert domain-record into raw-bytes"""
        return ctx.domain_to_bytes(getattr(self, self._key))

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> '_DomainRecordContent':
        """convert domain-record into raw-bytes"""
        domain, _ = ctx.domain_from_bytes(raw)
        return cls(domain)

class CNAME(_DomainRecordContent):
    _key = 'cname'
    const = Type.CNAME

    def __init__(self, cname: str):
        """
        :param cname: domain-address that declares an alias of the domain
        """
        self.cname = cname

class MX(RecordContent):
    const = Type.MX

    def __init__(self, preference: int, exchange: str):
        """
        :param preference: preference of exchange given
        :param exchange:   domain for a mail exchange
        """
        self.preference = preference
        self.exchange = exchange

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert mx-record into raw-bytes"""
        validate_int('preference', preference, 16)
        return (
            ctx.pack('>H', self.preference) +
            ctx.domain_to_bytes(self.exchange)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'MX':
        """convert raw-bytes into mx-record"""
        preference  = ctx.unpack('>H', raw[:2])[0]
        exchange, _ = ctx.domain_from_bytes(raw[2:])
        return cls(preference=preference, exchange=exchange)

class NS(_DomainRecordContent):
    _key = 'nameserver'
    const = Type.NS

    def __init__(self, nameserver: str):
        """
        :param cname: domain-address that declares an alias of the domain
        """
        self.nameserver = nameserver

class PTR(_DomainRecordContent):
    _key  = 'ptrname'
    const = Type.PTR

    def __init__(self, ptrname: str):
        """
        :param ptrname: domain which points to some location in domain space
        """
        self.ptrname = ptrname

class SOA(RecordContent):
    const = Type.SOA

    def __init__(self,
        mname:     str,
        rname:     str,
        serialver: int,
        refresh:   int,
        retry:     int,
        expire:    int,
        minimum:   int,
    ):
        """
        :param mname:     domain name of original or primary source for zone
        :param rname:     specifies mailbox of person responsible for this zone
        :param serialver: version number of original copy of this zone
        :param refresh:   interval before the zone should be refreshed
        :param retry:     interval before a failed refresh should be retried
        :param expire:    upper interval on time elapsed before zone loses auth
        :param minimum:   minimum TTL field that should be exported w/ any RR
        """
        self.mname      = mname
        self.rname      = rname
        self.serialver  = serialver
        self.refresh    = refresh
        self.retry      = retry
        self.expire     = expire
        self.minimum    = minimum

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert soa-record into raw-bytes"""
        validate_int('serialver', self.serialver, 32)
        validate_int('refresh', self.refresh, 32)
        validate_int('retry', self.retry, 32)
        validate_int('expire', self.expire, 32)
        validate_int('minimum', self.minimum, 32)
        return (
            ctx.domain_to_bytes(self.mname) +
            ctx.domain_to_bytes(self.rname) +
            ctx.pack('>I', self.serialver)  +
            ctx.pack('>I', self.refresh)    +
            ctx.pack('>I', self.retry)      +
            ctx.pack('>I', self.expire)     +
            ctx.pack('>I', self.minimum)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'SOA':
        """convert raw-bytes into soa-record"""
        mname, idx1 = ctx.domain_from_bytes(raw)
        rname, idx2 = ctx.domain_from_bytes(raw[idx1:])
        raw         = raw[idx1+idx2:]
        return cls(
            mname=mname,
            rname=rname,
            serialver=ctx.unpack('>I', raw[:4]),
            refresh=ctx.unpack('>I', raw[4:8]),
            retry=ctx.unpack('>I', raw[8:12]),
            expire=ctx.unpack('>I', raw[12:16]),
            minimum=ctx.unpack('>I', raw[16:]),
        )

class TXT(RecordContent):
    const = Type.TXT

    def __init__(self, text: str):
        """
        :param txt: text to include in the record object
        """
        self.txt = text

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert txt-record into raw-bytes"""
        text = self.txt.encode('utf-8')
        validate_int('len(text)', len(text), 8)
        ctx._idx += len(text)
        return ctx.pack('>B', len(text)) + text

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'TXT':
        """convert raw-bytes into txt-record"""
        txtlen = raw[0] + 1
        ctx._idx += txtlen
        return cls(raw[1:txtlen])

class A(RecordContent):
    const = Type.A

    def __init__(self, ipv4: Union[str, bytes]):
        """
        :param ipv4: ipv4 address assigned to a-record
        """
        self.ipv4 = ipaddress.IPv4Address(ipv4)

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert a-record into raw-bytes"""
        ctx._idx += 4
        return self.ipv4.packed

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'A':
        """convert raw-bytes into a-record"""
        ctx._idx += 4
        return cls(ipv4=raw[:4])

class AAAA(RecordContent):
    const = Type.AAAA

    def __init__(self, ipv6: Union[str, bytes]):
        """
        :param ipv6: ipv6 address assigned to a-record
        """
        self.ipv6 = ipaddress.IPv6Address(ipv6)

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert aaaa-record into raw-bytes"""
        return self.ipv6.packed

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'AAAA':
        """convert raw-bytes into aaaa-record"""
        return cls(ipv6=raw)
