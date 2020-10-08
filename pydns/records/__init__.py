"""
"""

#** Variables **#
__all__ = [
    'ResourceRecord',

    'RecordContent',
    'Empty',
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

from .records import *
from .content import *
