"""
Custom Rule Engine for Blocking Unwanted Domains
"""
from abc import abstractmethod
from typing import ClassVar, List, Optional, Protocol, Set

from pyderive import dataclass, field

from .. import RType, Answers, Backend

#** Variables **#
__all__ = [
    'RuleEngine',
    'RuleBackend',

    'DbmRuleEngine',
]

#** Functions **#

def split_domains(domain: bytes) -> List[bytes]:
    """
    split base-domain into all possible subdomains
    example: www.example.com => [www.example.com, example.com]

    :param domain: domain to be split into items
    :return:       split domain list
    """
    domains = []
    while domain.count(b'.') > 0:
        domains.append(domain)
        _, domain = domain.split(b'.', 1)
    return domains

#** Classes **#

class RuleEngine(Protocol):
    """
    Abstract Rule Engine Implementation for Domain Blocking
    """

    @abstractmethod
    def match_domain(self, domain: bytes) -> Optional[bool]:
        raise NotImplementedError

    @abstractmethod
    def match_pattern(self, domain: bytes) -> Optional[bool]:
        raise NotImplementedError

    def match(self, domain: bytes) -> Optional[bool]:
        """
        check if domain is contained within the database

        :param domain: domain to check if in db
        :return:       true if domain in db
        """
        for match in split_domains(domain):
            rule = self.match_domain(match)
            if rule is not None:
                return rule
        return self.match_pattern(domain)

@dataclass(slots=True, repr=False)
class RuleBackend(Backend):
    """
    Custom Rule Engine Backend for Blacklisting Unwanted Domains
    """
    source: ClassVar[str] = 'Blacklist'

    backend:   Backend
    blacklist: Set[bytes]           = field(default_factory=set)
    whitelist: Set[bytes]           = field(default_factory=set)
    engine:    Optional[RuleEngine] = None

    def __post_init__(self):
        self.recursion_available = self.backend.recursion_available
        self.empty = Answers([], self.source)
        self.blacklist -= self.whitelist

    def is_authority(self, domain: bytes) -> bool:
        """
        :param domain: check if domain is authority
        :return:       true if backend has authority over domain
        """
        return self.backend.is_authority(domain)

    def is_blocked(self, domain: bytes) -> bool:
        """
        check if the following domain is blocked

        :param domain: domain to check if blocked
        :return:       true if domain is blocked else false
        """
        # check if domain in in-memory whitelist of blacklist
        domains = split_domains(domain)
        if any(match in self.whitelist for match in domains):
            return False
        if any(match in self.blacklist for match in domains):
            return True
        # check if record in database
        if self.engine:
            # match against exact domain
            for match in domains:
                matches = self.engine.match_domain(match)
                if matches is True:
                    self.blacklist.add(domain)
                    self.blacklist.add(match)
                    return True
                if matches is False:
                    self.whitelist.add(domain)
                    self.whitelist.add(match)
                    return False
            # match against patterns
            matches = self.engine.match_pattern(domain)
            if matches is True:
                self.blacklist.add(domain)
                return True
            if matches is False:
                self.whitelist.add(domain)
                return False
        return False

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        block lookups for blacklisted domains, otherwise do standard query

        :param domain: domain to check if blocked or return results
        :param rtype:  record-type associated w/ query
        :return:       empty-answers (if blocked), else standard search results
        """
        if self.is_blocked(domain):
            return self.empty
        return self.backend.get_answers(domain, rtype)

#** Imports **#
from .database import DbmRuleEngine
