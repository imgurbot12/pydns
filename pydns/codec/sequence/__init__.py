"""
Sequence Implementation
"""

#** Variables **#
__all__ = [
    'Property',
    'InitVar',
    'ClassVar',
    
    'sequence',
    'make_sequence',
    'Sequence',
]

#** Imports **#
from .fields import Property, InitVar, ClassVar
from .sequence import sequence, make_sequence, Sequence
