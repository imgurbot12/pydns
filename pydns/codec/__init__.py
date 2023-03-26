"""
DNS Encoding/Decoding Helpers
"""
from dataclasses import field, InitVar
from typing import ClassVar

from .base import Context, Codec, Int, SizedBytes, IpAddress, Domain

#** Variables **#
__all__ = [
    'Context',
    'Codec',
    
    'Int',
    'Int8',
    'Int16',
    'Int32',
    'Int48',
    'Int64',

    'IpAddress',
    'Ipv4',
    'Ipv6',

    'Domain',
    'SizedBytes',

    'field',
    'sequence',
    'make_sequence',
    'Sequence',
    'Property',
    'InitVar',
    'ClassVar',
]

Int8  = Int[8]
Int16 = Int[16]
Int32 = Int[32]
Int48 = Int[48]
Int64 = Int[64]

Ipv4 = IpAddress['ipv4']
Ipv6 = IpAddress['ipv6']

#** Imports **#
from .sequence import sequence, make_sequence, Property, Sequence
