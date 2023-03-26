"""
Python Simple DNS Library
"""

#** Variables **#
__all__ = [
    'QR',
    'RType',
    'RClass',

    'Flags',
    'Answer',
    'PreRequisite',
    'Update',
    'Message', 
    'Question',
    'Zone',

    'EdnsAnswer',

    'CNAME',
    'MX',
    'NS',
    'PTR',
    'SOA',
    'A',
    'AAAA',
    'SRV'
]

#** Imports **#

from .flags import Flags
from .enum import QR, RType, RClass
from .answer import Answer, PreRequisite, Update
from .message import Message
from .question import Question, Zone
from .edns import EdnsAnswer
from .content import *
