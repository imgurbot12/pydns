import datetime
import ipaddress
from typing import Union, Optional

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
    'AAAA',
    'SRV',
    'TSIG',
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
        validate_int('preference', self.preference, 16)
        return (
            ctx.pack('>H', self.preference) +
            ctx.domain_to_bytes(self.exchange)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'MX':
        """convert raw-bytes into mx-record"""
        preference  = ctx.unpack('>H', raw[:2])
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

    def __init__(self, txt: str):
        """
        :param txt: text to include in the record object
        """
        self.txt = txt

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
        ctx._idx += len(self.ipv6.packed)
        return self.ipv6.packed

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'AAAA':
        """convert raw-bytes into aaaa-record"""
        ctx._idx += len(raw)
        return cls(ipv6=raw)

class SRV(RecordContent):
    const = Type.SRV

    def __init__(self, priority: int, weight: int, port: int, target: str):
        """
        :param priority: priority of the target host
        :param weight:   relative weight for those with same priority
        :param port:     port of service on target
        :param target:   domain of service being given
        """
        self.priority = priority
        self.weight   = weight
        self.port     = port
        self.target   = target

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert srv-record into bytes"""
        validate_int('priority', self.priority, 16)
        validate_int('weight', self.weight, 16)
        validate_int('port', self.port, 16)
        return (
            ctx.pack('>HHH', self.priority, self.weight, self.port) +
            ctx.domain_to_bytes(self.target)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'SRV':
        """convert raw-bytes into srv-record"""
        priority, weight, port = ctx.unpack('>HHH', raw[:6])
        target, _  = ctx.domain_from_bytes(raw[6:])
        return cls(priority, weight, port, target)

class TSIG:
    const = Type.TSIG

    def __init__(self,
        alg_name:    str,
        time_signed: datetime.datetime,
        fudge:       int,
        mac:         bytes,
        original_id: int,
        error_code:  RCode           = 0,
        other_data:  Optional[bytes] = None,
    ):
        """
        :param alg_name:    name of the algorithm in domain name syntax
        :param time_signed: seconds since 1-Jan-70 UTC
        :param fudge:       seconds of error permitted in time_signed
        :param mac:         defined by algorithm name
        :param orignal_id:  original message ID
        :param error_code:  expanded RCODE covering TSIG processing
        :param other_data:  empty unless Error == BADTIME
        """
        self.alg_name    = alg_name
        self.time_signed = time_signed
        self.fudge       = fudge
        self.mac         = mac
        self.original_id = original_id
        self.error_code  = error_code
        self.other_data  = other_data or b''

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert tsig-object into raw-bytes"""
        validate_int('fudge', self.fudge, 16)
        validate_int('mac_len', len(self.mac), 16)
        validate_int('original_id', self.original_id, 16)
        validate_int('error_code', self.error_code, 16)
        validate_int('other_data_len', len(self.other_data), 16)
        # shift index for any non ctx packed data after rendering domain
        ts        = int(self.time_signed.timestamp())
        domain    = ctx.domain_to_bytes(self.alg_name)
        ctx._idx += len(self.mac) + len(self.other_data)
        # generate bytes
        return (
            domain                                     +
            ctx.pack('>X', ts)                         +
            ctx.pack('>HH', self.fudge, len(self.mac)) +
            self.mac                                   +
            ctx.pack('>HHH',
                self.original_id,
                self.error_code,
                len(self.other_data)
            )                                          +
            self.other_data
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'TSIG':
        """convert raw-bytes into tsig-objects"""
        algname, idx                  = ctx.domain_from_bytes(raw)
        raw                           = raw[idx:]
        time_signed                   = ctx.unpack('>X', raw[:6])
        fudge, mlen                   = ctx.unpack('>HH', raw[6:10])
        mlen                         += 10
        mac, raw                      = (raw[10:mlen], raw[mlen:])
        original_id, error_code, olen = ctx.unpack('>HHH', raw[:6])
        other_data                    = raw[6:olen+6]
        return cls(
            alg_name=algname,
            time_signed=datetime.datetime.fromtimestamp(time_signed),
            fudge=fudge,
            mac=mac,
            original_id=original_id,
            error_code=error_code,
            other_data=other_data,
        )
