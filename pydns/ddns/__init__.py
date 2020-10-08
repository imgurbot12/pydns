"""
extension of dns to allow dynamic updates to records within the system
"""

#** Variables **#
__all__ = [
    'Zone',
    'PreRequisite',
    'Update',

    'ANY',
    'NULL',
]

from .ddns import *
from .content import *
