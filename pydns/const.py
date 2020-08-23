"""
"""
import enum
import struct
from typing import Tuple

#** Variables **#
__all__ = [
    'DNSError',
    'IntError',
    'PacketTruncated',

    'validate_int',

    'SerialCtx',

    'QR',
    'OpCode',
    'RCode',
    'Type',
    'Class',
    'EDNSOption',
]

_bitmax = {
    4:  2**4,
    8:  2**8,
    16: 2**16,
    32: 2**32,
    48: 2**48,
}

#** Errors **#

class DNSError(Exception):
    """base-class dns exception"""
    pass

class IntError(DNSError):
    """raise this error if integer is too large or too small"""
    pass

class PacketTruncated(DNSError):
    """raise this error if deserilization runs out of bytes to read"""
    pass

class InvalidDomainPtr(DNSError):
    """domain pointer points to invalid domain offset"""
    pass

#** Functions **#

def validate_int(key: str, i: int, bits: int = 16) -> int:
    """raise error if integer is over the max value allowed"""
    max = _bitmax[bits]
    if i < 0 or i >= max:
        raise IntError('%s too big for %dbit int: %r' % (key, bits, i))
    return i

#** Classes **#

class SerialCtx:

    def __init__(self):
        self.reset()

    def reset(self):
        self._idx = 0
        self._idx_domain = {}
        self._domain_idx = {}

    def _new_domain(self, name: str, idx: int):
        self._idx_domain[idx] = name
        self._domain_idx[name] = idx

    def _domain_to_ptr(self, name: str):
        """convert a given domain-address into raw-bytes ptr"""
        ptr1, ptr2 = struct.pack('>H', self._domain_idx[name])
        ptr1      |= 0b11000000
        return bytes([ptr1, ptr2])

    def _ptr_to_domain(self, raw: bytes) -> str:
        """convert given ptr address to domain-name"""
        ptr1, ptr2 = raw[:2]
        if (ptr1 & 0b11000000) == 192:
            ptr1 &= 0b00111111
            ptr   = struct.unpack('>H', bytes([ptr1, ptr2]))[0]
            if ptr not in self._idx_domain:
                raise Exception('ptr not found')
            return self._idx_domain[ptr]

    def domain_to_bytes(self, domain: str) -> bytes:
        """convert domain-name into raw-bytes w/ ptrs if applicable"""
        # generate chunks for domain bytes
        (idx, chunks, name) = (self._idx, [], domain[:]+'..')
        while name:
            # check if ptr can be used w/ subname and assign rather than chunk
            subname = name[:-2]
            if subname:
                if subname in self._domain_idx:
                    chunks.append( self._domain_to_ptr(subname) )
                    idx += 2
                    break
                # if ptr has not been found. keep reference of subname in
                # case ptr can be used later
                self._new_domain(subname, idx)
            # assign chunk to outputed chunks
            chunk, name = name.split('.', 1)
            idx        += len(chunk) + 1
            chunks.append( struct.pack('>B', len(chunk)) + chunk.encode() )
        # concatenate chunks into new bytes domain
        self._idx = idx
        return b''.join(chunks)

    def domain_from_bytes(self, raw: bytes) -> Tuple[str, int]:
        """convert raw-bytes into the given domain"""
        (idx, chunks, byte) = (0, [], 2)
        while byte > 1:
            byte = raw[0] + 1
            # check if ptr exists at start of next chunk
            if len(raw) >= 2:
                domain = self._ptr_to_domain(raw)
                if domain:
                    chunks.append( (idx, domain) )
                    idx += 2
                    break
            # else, get length and collect chunk
            chunk, raw = (raw[1:byte], raw[byte:])
            if chunk:
                chunks.append( ( idx, chunk.decode() ) )
            idx += len(chunk) + 1
        # append chunks to domains
        for n, (subidx, chunk) in enumerate(chunks, 0):
            subname = '.'.join(ch for _,ch in chunks[n:])
            if subname not in self._domain_idx:
                self._new_domain(subname, subidx + self._idx)
        # return complete domain
        self._idx += idx
        return ('.'.join(ch for _, ch in chunks), idx)

    def tohex(self, raw: bytes) -> str:
        """
        convert raw-bytes into hex

        :param raw: raw-bytes
        :return:    newly generated hex string
        """
        self._idx += len(raw)
        return raw.hex()

    def fromhex(self, hex: str) -> bytes:
        """
        convert hex-string into raw-bytes

        :param hex: hex-string
        :return:    raw-bytes
        """
        raw = bytes.fromhex(hex)
        self._idx += len(raw)
        return raw

    def pack(self, fmt: str, num: int) -> bytes:
        """
        convert given number in the relevant packed integer

        :param fmt: struct pack format (ex: >H == 16bit-int)
        :param num: number being packed into bytes
        :return:    raw-bytes representing integer
        """
        # 6byte integer not supported, so package like 8byte and trim bytes
        if fmt == '>X':
            packed = struct.pack('>Q', num)[2:]
        else:
            packed = struct.pack(fmt, num)
        self._idx += len(packed)
        return packed

    def unpack(self, fmt: str, raw: bytes) -> int:
        """
        convert given bytes into the relevant packed integer

        :param fmt: struct pack format (ex: >H == 16bit-int)
        :param raw: raw-bytes being converted to integer
        :return:    number parsed from raw-bytes
        """
        # 6bytes integer not supported, so act like an 8byte one
        if fmt == '>X':
            fmt = '>Q'
            raw = b'\x00\x00' + raw
        # shift idx and unpack integer
        self._idx += len(raw)
        unpacked = struct.unpack(fmt, raw)[0]
        return unpacked

#** Enums **#

class QR(enum.IntEnum):
    Question = 0 << 7
    Response = 1 << 7

class OpCode(enum.IntEnum):
    Query        = 0 << 3
    InverseQuery = 1 << 3
    Status       = 2 << 3
    Notify       = 4 << 3
    Update       = 5 << 3

class RCode(enum.IntEnum):
    NoError           = 0
    FormatError       = 1
    ServerFailure     = 2
    NonExistantDomain = 3
    NotImplemented    = 4
    Refused           = 5
    YXDomain          = 6
    YXRRSet           = 7
    NXRRSet           = 8
    NotAuthorized     = 9
    NotInZone         = 10

    BadOPTVersion     = 16
    BadSignature      = 16
    BadKey            = 17
    BadTime           = 18
    BadMode           = 19
    BadName           = 20
    BadAlgorithm      = 21

class Type(enum.IntEnum):
    A     = 1
    NS    = 2
    MD    = 3
    MF    = 4
    CNAME = 5
    SOA   = 6
    MB    = 7
    MG    = 8
    MR    = 9
    NULL  = 10
    WKS   = 11
    PTR   = 12
    HINFO = 13
    MINFO = 14
    MX    = 15
    TXT   = 16
    AAAA  = 28
    SRV   = 33
    OPT   = 41

    DS     = 43
    RRSIG  = 46
    NSEC   = 47
    DNSKEY = 48

    TSIG  = 250

    AXFR  = 252
    MAILB = 253
    MAILA = 254
    ANY   = 255

class Class(enum.Enum):
    IN   = 1
    CS   = 2
    CH   = 3
    HS   = 4
    NONE = 254
    ANY  = 255

class EDNSOption(enum.IntEnum):
    Cookie = 10

class DNSSecAlgorithm(enum.IntEnum):
    RSA_MD5        = 1
    DH             = 2
    DIFFIE_HELMEN  = 2
    DSA            = 3
    DSA_SHA1       = 3
    ECC            = 4
    ELIPTIC_CURVE  = 4
    RSA_SHA1       = 5

    DSA_NSEC3_SHA1     = 6
    RSASHA1_NSEC3_SHA1 = 7
    RSA_SHA256         = 8
    RSA_SHA512         = 10
    ECC_GOST           = 12
    ECDSA_P256_SHA256  = 13
    ECDSA_P384_SHA384  = 14
    ED25519            = 15
    ED448              = 16

    INDIRECT      = 252
    PRIVATE_DNS   = 253
    PRIVATE_OID   = 254

class DNSSecDigestType(enum.IntEnum):
    SHA1     = 1
    SHA256   = 2
    ECC_GOST = 3
    SHA_384  = 4
