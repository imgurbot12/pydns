"""
Simple Python DNS Library
"""

#** Variables **#
__all__ = [
    'BaseAnswer',
    'Answer',
    'PreRequisite',
    'Update',

    'Content',
    'Unknown',
    'NULL',
    'ANY',
    'CNAME',
    'MX',
    'NS',
    'PTR',
    'SOA',
    'TXT',
    'A',
    'AAAA',
    'SRV',

    'QR',
    'OpCode',
    'RCode',
    'RType',
    'RClass',
    'EDNSOption',

    'DnsError',
    'ServerFailure',
    'NonExistantDomain',
    'NotImplemented',

    'Flags',
    'Message',

    'Question',
    'Zone'
]

#** Imports **#
from .answer import *
from .content import *
from .enum import *
from .exceptions import *
from .flags import *
from .message import *
from .question import *
