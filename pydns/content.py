"""
DNS Standard Content Sequences
"""
from typing import Optional

from .codec import *
from .enum import RType

#** Variables **#
__all__ = [
    'NULL',
    'ANY',
    'CNAME',
    'MX',
    'NS',
    'PTR',
    'SOA',
    'A',
    'AAAA',
    'SRV'
]

#** Functions **#

def content(cls: Optional[type] = None, rtype: Optional[RType] = None):
    """generate content class w/ given rtype"""
    def wrapper(cls):
        cls.rtype = rtype or RType[cls.__name__] 
        return make_sequence(cls)
    return wrapper if cls is None else wrapper(cls)

#** Classes **#

class Content(Sequence):
    rtype: ClassVar[RType]

@content
class NULL(Content):
    pass

@content
class ANY(Content):
    pass

@content
class CNAME(Content):
    name: Domain

@content
class MX(Content):
    preference: Int16
    exchange:   Domain

@content
class NS(Content):
    nameserver: Domain

@content
class PTR(Content):
    ptrname: Domain

@content
class SOA(Content):
    mname:     Domain
    rname:     Domain
    serialver: Int32
    refresh:   Int32
    retry:     Int32
    expire:    Int32
    minimum:   Int32

@content
class TXT(Content):
    text: SizedBytes[32]

@content
class A(Content):
    ip: Ipv4

@content
class AAAA(Content):
    ip: Ipv6

@content
class SRV(Content):
    priority: Int16
    weight:   Int16
    port:     Int16
    target:   Domain
