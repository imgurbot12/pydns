"""
"""
import datetime
from typing import Set

from ..const import SerialCtx, Type, DNSSecAlgorithm, DNSSecDigestType
from ..records import RecordContent

from .flags import DNSKeyFlags

#** Variables **#
__all__ = [
    'DS',
    'NSEC',
    'RRSIG',
    'DNSKEY'
]

#** Classes **#

class DS(RecordContent):
    const = Type.DS

    def __init__(self,
        keyid:     int,
        algorithm: DNSSecAlgorithm,
        dtype:     DNSSecDigestType,
        digest:    str,
    ):
        """
        :param keyid:     unique identifier linked to DNSKEY RR
        :param algorithm: algorithm number used by DNSKEY RR
        :param dtype:     algorithm used to calculate digest
        :param digest:    digest of DNSKEY RR
        """
        self.keyid       = keyid
        self.algorithm   = algorithm
        self.digest_type = dtype
        self.digest      = digest

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert ds-record into bytes"""
        validate_int('keyid', self.keyid, 16)
        alg   = self.algorithm.value
        dtype  = self.digest_type.value
        return (
            ctx.pack('>HBB', self.keyid, alg, dtype) +
            ctx.fromhex(self.digest)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'DS':
        """convert raw-bytes into ds-record"""
        keyid, alg, dtype = ctx.unpack('>HBB', raw[:4])
        return cls(
            keyid=keyid,
            algorithm=DNSSecAlgorithm(alg),
            dtype=DNSSecDigestType(dtype),
            digest=ctx.tohex(raw[4:])
        )

class RRSIG(RecordContent):
    const = Type.RRSIG

    def __init__(self,
        covered:      Type,
        algorithm:    DNSSecAlgorithm,
        labels:       int,
        original_ttl: datetime.timedelta,
        expiration:   datetime.datetime,
        inception:    datetime.datetime,
        keyid:        int,
        signer_name:  str,
        signature:    str,
    ):
        """
        :param covered:      RR Type covered by this signature
        :param algorithm:    algorithm used to generate signature
        :param labels:       num of labels in the original RRSIG RR owner name
        :param original_ttl: TTL of the covered RRset in authorative zone
        :param expiration:   datetime of end of signature life
        :param inception:    datetime of start of signature life
        :param keyid:        unique identifier related to DNSKEY RR
        :param signer_name:  owner name of the DNSKEY RR
        :param signature:    the cryptographic signature that covers the RRSIG
        """
        self.covered      = covered
        self.algorithm    = algorithm
        self.labels       = labels
        self.original_ttl = original_ttl
        self.expiration   = expiration
        self.inception    = inception
        self.keyid        = keyid
        self.signer_name  = signer_name
        self.signature    = signature

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert rrsig-record into raw-bytes"""
        return (
            ctx.pack('>HBBIIIH',
                self.covered.value,
                self.algorithm.value,
                self.labels,
                self.original_ttl.seconds,
                int(self.expiration.timestamp()),
                int(self.inception.timestamp()),
                self.keyid,
            ) +
            ctx.domain_to_bytes(self.signer_name) +
            ctx.fromhex(self.signature)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'RRSIG':
        """convert raw-bytes into rrsig-record"""
        (
            covered, alg, labels, orig_ttl, expiration, inception, keyid,
        ) = ctx.unpack('>HBBIIIH', raw[:18])
        signer_name, idx = ctx.domain_from_bytes(raw[18:])
        return cls(
            covered=Type(covered),
            algorithm=DNSSecAlgorithm(alg),
            labels=labels,
            orignal_ttl=datetime.timedelta(seconds=orig_ttl),
            expiration=datetime.datetime.fromtimestamp(expiration),
            inception=datetime.datetime.fromtimestamp(inception),
            keyid=keyid,
            signer_name=signer_name,
            signature=ctx.tohex(raw[18+idx:])
        )

class NSEC(RecordContent):
    const = Type.NSEC

    def __init__(self, next_domain: str, record_types: Set[Type]):
        """
        :param next_domain:  next domain that has authoritative data
        :param record_types: identifies the RRset types that exist in RR owners
        """
        self.next_domain  = next_domain
        self.record_types = record_types

    @staticmethod
    def _types_to_bitmap(record_types: Set[Type]) -> bytes:
        """convert record-types into bitmap used by NSEC"""
        # create bit-array and assign record-type integers to bits
        bits = ['0']
        for r in record_types:
            while r.value >= len(bits):
                bits += ['0']*len(bits)
            bits[r.value] = '1'
        # convert bit-array to byte-array
        byt = []
        for byte in (bits[i:i+8] for i in range(0, len(bits), 8)):
            b = 0
            for bit in byte:
                b <<= 1
                b |= int(bit)
            byt.append(b)
        return bytes(byt).rstrip(b'\x00')

    @staticmethod
    def _bitmap_to_types(raw: bytes) -> Set[Type]:
        """convert bitmap into record-types used by NSEC"""
        bits = (
            bit == '1'
            for c in ('{:08b}'.format(b) for b in raw)
            for bit in c
        )
        return [Type(rt) for rt, ex in enumerate(bits, 0) if ex]

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert nsec-record into raw-bytes"""
        domain    = ctx.domain_to_bytes(self.next_domain)
        bitmap    = self._types_to_bitmap(self.record_types)
        ctx._idx += len(bitmap)
        return (domain + bitmap)

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx)  -> 'NSEC':
        """convert raw-bytes into nsec-record"""
        next_domain, idx = ctx.domain_from_bytes(raw)
        return cls(
            next_domain=next_domain,
            record_types=cls._bitmap_to_types(raw[idx:])
        )

class DNSKEY(RecordContent):
    const = Type.DNSKEY

    def __init__(self,
        flags:    DNSKeyFlags,
        protocol: int,
        alg:      DNSSecAlgorithm,
        key:      str,
    ):
        """
        :param flags:    dnskey-flags used to declare specifics about key
        :param protocol: MUST always be 3 or be counted as invalid
        :param alg:      algorithm to compute public-key
        :param key:      public-key calulated w/ given algorithm
        """
        self.flags      = flags
        self.protocol   = protocol
        self.algorithm  = alg
        self.public_key = public_key

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert dnskey-record into raw-bytes"""
        return (
            self.flags.to_bytes(ctx) +
            ctx.pack('>BB', self.protocol, self.algorithm) +
            ctx.fromhex(self.public_key)
        )

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'DNSKEY':
        """convert raw-bytes into dnskey-record"""
        protocol, alg = ctx.unpack('>BB', ctx[2:4])
        return cls(
            flags=DNSKeyFlags.from_bytes(ctx[:2]),
            protocol=protocol,
            alg=alg,
            key=ctx.tohex(raw[4:])
        )
