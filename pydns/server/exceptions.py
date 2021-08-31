"""
contains custom exceptions raised during various DNS errors
"""
from ..const import RCode

#** Variables **#
__all__ = [
    'DNSException',

    'FormatError',
    'NoSuchDomain',
    'Refused',
    'DomainExists',
    'RequisiteExists',
    'NoSuchRequisite',
    'NotAuthorized',
    'NotInZone',
]

#** Classes **#

class DNSException(Exception):
    """baseclass DNS exception object used for basic server-failure"""
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
