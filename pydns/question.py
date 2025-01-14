"""
DNS Question Object Definitions
"""
from pystructs import U16, Domain, Struct
from typing_extensions import Annotated

from .enum import RType, RClass

#** Variables **#
__all__ = ['Question', 'Zone']

#** Classes **#

class Question(Struct):
    """
    DNS Question Object Definition
    """
    name:   Domain
    qtype:  Annotated[RType, U16]
    qclass: Annotated[RClass, U16] = RClass.IN

class Zone(Question):
    """
    Alias of Question in UPDATE action DNS Requests
    """
    pass
