"""
Custom Rule Engine for Blocking Unwanted Domains
"""
from enum import Enum
from abc import abstractmethod
from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar, List, Optional, Protocol, Set

from pyderive import dataclass, field
from pydns import A, AAAA, Answer, RCode

from .. import RType, Answers, Backend

#** Variables **#
__all__ = [
    'RStatus',
    'BlockMode',
    'RuleEngine',
    'RuleBackend',

    'RuleEngineDB',
]

NULL_IPV4 = A(IPv4Address('0.0.0.0'))
NULL_IPV6 = AAAA(IPv6Address('::'))

#** Functions **#

def split_domains(domain: bytes) -> List[bytes]:
    """
    Split base-domain into all possible subdomains
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

class RStatus(int, Enum):
    BLACKLIST = 0
    WHITELIST = 1

class BlockMode(str, Enum):
    """
    Block behavior for Rule Engine
    """

    NODATA = 'nodata'
    """Return an empty success response with no records"""
    NULL = 'null'
    """Return localhost address (0.0.0.0 or ::) to prevent routing"""
    NXDOMAIN = 'nxdomain'
    """Raise NXDOMAIN error indicating domain does not exist"""

    def get_answers(self, domain: bytes, rtype: RType, source: str) -> Answers:
        """
        Generate answers based on block-mode

        :param domain: question domain
        :param rtype:  question requested record-type
        :return:       list of associated answers
        """
        if self == self.NULL:
            if rtype == RType.A:
                return Answers([Answer(domain, 60, NULL_IPV4)], source)
            if rtype == RType.AAAA:
                return Answers([Answer(domain, 60, NULL_IPV6)], source)
        if self == self.NXDOMAIN:
            return Answers([], source, RCode.NonExistantDomain)
        return Answers([], source)

class RuleEngine(Protocol):
    """
    Abstract Rule Engine Implementation for Domain Blocking
    """

    @abstractmethod
    async def count_blocked(self) -> int:
        """
        Count the number of blocked entries in engine
        """
        raise NotImplementedError

    @abstractmethod
    async def match_domain(self, domain: bytes) -> Optional[RStatus]:
        """
        Check if a domain matches an engine rule and if its white/blacklisted
        """
        raise NotImplementedError

    @abstractmethod
    async def match_pattern(self, domain: bytes) -> Optional[RStatus]:
        """
        Check if a domain matches an engine pattern and if its white/blacklisted
        """
        raise NotImplementedError

    async def match(self, domain: bytes) -> Optional[RStatus]:
        """
        Check if domain is contained within the database

        :param domain: domain to check if in db
        :return:       true if domain in db
        """
        rule = await self.match_domain(*split_domains(domain))
        if rule is not None:
            return rule
        return await self.match_pattern(domain)

class RuleBackend(Backend):
    """
    Custom Rule Engine Backend for Blacklisting Unwanted Domains
    """
    __slots__ = ('backend', 'whitelist', 'blacklist', 'engine', 'block_mode')

    source: ClassVar[str] = 'Blacklist'

    def __init__(self,
        backend:    Backend,
        blacklist:  Optional[Set[bytes]] = None,
        whitelist:  Optional[Set[bytes]] = None,
        engine:     Optional[RuleEngine] = None,
        block_mode: BlockMode            = BlockMode.NODATA,
    ):
        self.backend             = backend
        self.whitelist           = (whitelist or set())
        self.blacklist           = (blacklist or set()) - self.whitelist
        self.engine              = engine
        self.block_mode          = block_mode

    def recursion_available(self) -> bool:
        return self.backend.recursion_available()

    async def is_authority(self, domain: bytes) -> bool:
        return await self.backend.is_authority(domain)

    async def is_blocked(self, domain: bytes) -> bool:
        """
        Check if the following domain is blocked
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
                matches = await self.engine.match_domain(match)
                if matches is RStatus.BLACKLIST:
                    self.blacklist.add(domain)
                    self.blacklist.add(match)
                    return True
                if matches is RStatus.WHITELIST:
                    self.whitelist.add(domain)
                    self.whitelist.add(match)
                    return False
            # match against patterns
            matches = await self.engine.match_pattern(domain)
            if matches is RStatus.BLACKLIST:
                self.blacklist.add(domain)
                return True
            if matches is RStatus.WHITELIST:
                self.whitelist.add(domain)
                return False
        return False

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        Block lookups for blacklisted domains, otherwise do standard query
        """
        if await self.is_blocked(domain):
            return self.block_mode.get_answers(domain, rtype, self.source)
        return await self.backend.get_answers(domain, rtype)

    async def count_blocked(self) -> int:
        """
        Count number of blacklisted items in rule backend
        """
        blacklisted = len(self.blacklist)
        if self.engine is not None:
            blacklisted += await self.engine.count_blocked()
        return blacklisted + await self.backend.count_blocked()

#** Imports **#
from .database import RuleEngineDB
