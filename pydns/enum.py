"""
DNS Enumeration Definitions
"""
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
    """
    Message Operation-Code (QUESTION/RESPONSE)
    """
    Question = 0
    Response = 1

class OpCode(IntEnum):
    """
    Message Operation Code - Query, Inverse-Query, etc
    """
    Query        = 0
    InverseQuery = 1
    Status       = 2
    Notify       = 4
    Update       = 5

class RCode(IntEnum):
    """
    Message Response/Error Code
    """
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
    """
    Question/Action Resource Record (RR) Type
    """
    A          = 1
    NS         = 2
    MD         = 3
    MF         = 4
    CNAME      = 5
    SOA        = 6
    MB         = 7
    MG         = 8
    MR         = 9
    NULL       = 10
    WKS        = 11
    PTR        = 12
    HINFO      = 13
    MINFO      = 14
    MX         = 15
    TXT        = 16
    RP         = 17
    AFSDB      = 18
    X25        = 19
    ISDN       = 20
    RT         = 21
    NSAP       = 22
    NSAP_PTR   = 23
    SIG        = 24
    KEY        = 25
    AAAA       = 28
    LOC        = 29
    NXT        = 30
    EID        = 31
    NB         = 32
    SRV        = 33
    NAPTR      = 35
    KX         = 36
    CERT       = 37
    A6         = 38
    DNAME      = 39
    SINK       = 40
    OPT        = 41
    APL        = 42
    DS         = 43
    SSHFP      = 44
    IPSECKEY   = 46
    RRSIG      = 46
    NSEC       = 47
    DNSKEY     = 48
    DHCID      = 49
    NSEC3      = 50
    NSEC3PARAM = 51
    TLSA       = 52
    SMIMEA     = 53
    HIP        = 55
    NINFO      = 56
    RKEY       = 57
    TALINK     = 58
    CDS        = 59
    CDNSKEY    = 60
    OPENPGPKEY = 61
    CSYNC      = 62
    ZONEMD     = 63
    SVCB       = 64
    HTTPS      = 65

    SPF    = 99
    UINFO  = 100
    UID    = 101
    GID    = 102
    UNPSEC = 103
    NID    = 104
    L32    = 105
    L64    = 106
    LP     = 107
    EUI48  = 108
    EUI64  = 109

    TKEY  = 249
    TSIG  = 250
    AXFR  = 252
    MAILB = 253
    MAILA = 254
    ANY   = 255
    URI   = 256
    CAA   = 257
    DOTA  = 259

    TA  = 32768
    DLV = 32769

class RClass(IntEnum):
    """
    RR Classification (Almost Always IN - Internet)
    """
    IN   = 1
    CS   = 2
    CH   = 3
    HS   = 4
    NONE = 254
    ANY  = 255

class EDNSOption(IntEnum):
    """
    EDNS RR Options
    """
    Cookie = 10
