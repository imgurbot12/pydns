from enum import IntEnum

#** Variables **#
__all__ = [
    'QR',
    'OpCode',
    'RCode',
    'RType',
    'RClass',
    'EDNSOption',
]

#** Classes **#

class QR(IntEnum):
    Question = 0
    Response = 1

class OpCode(IntEnum):
    Query        = 0
    InverseQuery = 1
    Status       = 2
    Notify       = 4
    Update       = 5

class RCode(IntEnum):
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

class RType(IntEnum):
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
    NAPTR = 35
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

class RClass(IntEnum):
    IN   = 1
    CS   = 2
    CH   = 3
    HS   = 4
    NONE = 254
    ANY  = 255

class EDNSOption(IntEnum):
    Cookie = 10
