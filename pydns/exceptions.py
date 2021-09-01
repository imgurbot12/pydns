"""
contains custom exceptions raised during various DNS errors
"""
from typing import Optional

from .const import RCode

#** Variables **#
__all__ = [
    'DNSException',

    'ServerFailure',
    'FormatError',
    'NoSuchDomain',
    'Refused',
    'DomainExists',
    'RequisiteExists',
    'NoSuchRequisite',
    'NotAuthorized',
    'NotInZone',
]

#** Functions **#

def get_exception_by_code(code: RCode) -> Optional['DNSException']:
    """iterate exception types and try to match given code"""
    for ex in (
        ServerFailure,
        FormatError,
        NoSuchDomain,
        Refused,
        DomainExists,
        RequisiteExists,
        NoSuchRequisite,
        NotAuthorized,
        NotInZone,
    ):
        if ex.code == code:
            return ex
    return DNSException('server error occured', code)

#** Classes **#

class DNSException(Exception):
    """baseclass DNS exception object used for unexpected server errors"""
    code: RCode = None

    def __init__(self, message: str = '', code: RCode = RCode.ServerFailure):
        """specify code if not already declared for subclass & build message"""
        if self.code is None:
            self.code = code
        super().__init__('(code=%s) %s' % (self.code.name, message))

class ServerFailure(DNSException):
    """custom error used for basic server-failure"""
    code = RCode.ServerFailure

class FormatError(DNSException):
    """custom error when request specification is incorrect"""
    code = RCode.FormatError

class NoSuchDomain(DNSException):
    """custom error when requested domain does not exist"""
    code = RCode.NonExistantDomain

class NotImplemented(DNSException):
    """custom error when type of request is not implemented"""
    code = RCode.NotImplemented

class Refused(DNSException):
    """raise error when requested action is not allowed"""
    code = RCode.Refused

class DomainExists(DNSException):
    """raise error when domain exists when its not supposed to"""
    code = RCode.YXDomain

class RequisiteExists(DNSException):
    """raise error when requisite exists but its not supposed to"""
    code = RCode.YXRRSet

class NoSuchRequisite(DNSException):
    """raise error when requisite settings havent been met"""
    code = RCode.NXRRSet

class NotAuthorized(DNSException):
    """raise error when dns-server is not authorized to complete request"""
    code = RCode.NotAuthorized

class NotInZone(DNSException):
    """custom error raised when update does not match designated zone"""
    code = RCode.NotInZone
