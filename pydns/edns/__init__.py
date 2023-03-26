"""
Extension Mechanisms for DNS (EDNS0)
(rfc: https://www.rfc-editor.org/rfc/rfc2671)
"""

#** Variables **#
__all__ = ['ROOT', 'EdnsAnswer']

#** Imports **#
from .record import ROOT, EdnsAnswer
