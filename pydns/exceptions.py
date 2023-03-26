"""
DNS RCode Exceptions
"""
from typing import Dict, Type, Optional, Any

from .enum import RCode

#** Variables **#
__all__ = [
    'make_error',

    'DnsError',
    'ServerFailure',
    'NonExistantDomain',
    'NotImplemented',
]

_EXCEPTIONS: Dict[RCode, Type[Exception]] = {}

#** Functions **#

def make_error(rcode: RCode, message: Any = None):
    """
    retrieve best exception object to match the given rcode
    """
    # cache map of exceptions in module
    global _EXCEPTIONS
    if not _EXCEPTIONS:
        for value in globals().values():
            if isinstance(value, type) and issubclass(value, DnsError):
                _EXCEPTIONS[value.rcode] = value
    # retrieve best-matching exception class based on rcode
    eclass = _EXCEPTIONS.get(rcode, DnsError)
    raise eclass(message, rcode)

#** Classes **#

class DnsError(Exception):
    rcode: RCode = RCode.NoError

    def __init__(self, msg: Any = None, rcode: Optional[RCode] = None):
        self.message = msg
        self.rcode   = rcode or self.rcode

    def __str__(self) -> str:
        if self.message and self.__class__.rcode == self.rcode:
            return str(self.message)
        return super().__str__()

class ServerFailure(DnsError):
    rcode = RCode.ServerFailure

class NonExistantDomain(DnsError):
    rcode = RCode.NonExistantDomain

class NotImplemented(DnsError):
    rcode = RCode.NotImplemented
