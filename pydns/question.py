"""
DNS Question Implementation
"""
from .codec import *
from .enum import RType, RClass

#** Variables **#
__all__ = ['Question', 'Zone']

#** Classes **#

@make_sequence
class Question:
    name:   Domain
    qtype:  Int[16, RType, 'QType']
    qclass: Int[16, RClass, 'QClass'] = RClass.IN

class Zone(Question):
    """Alias of Question in UPDATE action DNS Requests"""
    pass
