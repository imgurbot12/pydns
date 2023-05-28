"""
DNS Question Implementation
"""
from typing_extensions import Annotated

from pystructs import Struct, U16, Wrap, Domain

from .enum import RType, RClass

#** Variables **#
__all__ = ['Question', 'Zone']

#** Classes **#

class Question(Struct):
    name:   Domain
    qtype:  Annotated[RType, Wrap[U16, RType]]
    qclass: Annotated[RClass, Wrap[U16, RClass]] = RClass.IN

class Zone(Question):
    """Alias of Question in UPDATE action DNS Requests"""
    pass
