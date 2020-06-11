"""
"""

#** Variables **#
__all__ = [
    'ResourceRecord',

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

from .records import *
from .content import *
