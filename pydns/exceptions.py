"""
DNS RCode Exceptions
"""
from typing import Any, Optional

from .enum import RCode

#** Variables **#
__all__ = [
    'DnsError',
    'ServerFailure',
    'NonExistantDomain',
    'NotImplemented',
]

#** Functions **#

def raise_error(rcode: RCode, message: Any = None):
    """
    raise best exception object to match the given rcode

    :param rcode:   response code from message
    :param message: message to include with exception
    """
    global EXCEPTION_MAP
    eclass = EXCEPTION_MAP.get(rcode, DnsError)
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

#** Exceptions **#

#: cheeky way of collecting all exception types into map based on their RCode
EXCEPTION_MAP = {v.rcode:v
    for v in globals().values()
    if isinstance(v, type) and issubclass(v, DnsError) and v is not DnsError}
