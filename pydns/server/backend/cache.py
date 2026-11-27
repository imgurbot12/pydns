"""
Backend Extension to support In-Memory Answer Caching
"""
import time
import math
from asyncio import Lock
from logging import Logger, getLogger
from typing import ClassVar, Dict, List, Optional, Set

from . import Answers, Backend, RType, Answer
from .memory import MemoryBackend
from .resolver import Resolver
from .ruleset import RuleBackend

#** Variables **#
__all__ = ['Cache']

#: default set of other backend sources to ignore
IGNORE = {Resolver.source, RuleBackend.source, MemoryBackend.source}

#** Classes **#

class CacheRecord:
    """
    Record Entry for In-Memory Cache
    """
    __slots__ = ('answers', 'expires', 'accessed')

    def __init__(self, answers: List[Answer], expiration: int):
        """
        Calculate expiration-time and last-accessed time
        """
        ttl = min(a.ttl for a in self.answers)
        ttl = min(ttl, expiration) if expiration else ttl
        now = time.time()
        self.answers  = answers
        self.expires  = now + ttl
        self.accessed = now

    def is_expired(self) -> bool:
        """
        Calculate if expiration has passed or TTL is expired
        """
        now = time.time()
        if self.expires <= now:
            return True
        elapsed = math.floor(now - self.accessed)
        if not elapsed:
            return False
        for answer in self.answers:
            answer.ttl -= elapsed
            if answer.ttl <= 0:
                return True
        self.accessed = now
        return False

class Cache(Backend):
    """
    In-Memory Cache Extension for Backend Results
    """
    __slots__ = (
        'backend', 'expiration', 'maxsize', 'ignore_rtypes', 'ignore_sources',
        'logger', 'mutex', 'cache', 'authorities')

    source: ClassVar[str] = 'Cache'

    cache:       Dict[str, CacheRecord]
    authorities: Dict[bytes, bool]

    def __init__(self,
        backend:        Backend,
        expiration:     int        = 30,
        maxsize:        int        = 10000,
        ignore_rtypes:  Optional[Set[RType]] = None,
        ignore_sources: Optional[Set[str]]   = None,
        logger:         Optional[Logger]     = None,
    ):
        self.backend             = backend
        self.expiration          = expiration
        self.maxsize             = maxsize
        self.ignore_rtypes       = ignore_rtypes or {RType.SOA, }
        self.ignore_sources      = ignore_sources or IGNORE
        self.logger              = logger or getLogger('pydns.cache')
        self.mutex               = Lock()
        self.cache               = {}
        self.authorities         = {}
        self.recursion_available = self.backend.recursion_available

    def recursion_available(self) -> bool:
        return self.backend.recursion_available()

    async def is_authority(self, domain: bytes) -> bool:
        """
        Retrieve if domain is authority from cache before checking backend
        """
        # check cache before querying backend
        if domain in self.authorities:
            return self.authorities[domain]
        # query backend and then permanently cache authority result
        authority = await self.backend.is_authority(domain)
        async with self.mutex:
            if len(self.authorities) >= self.maxsize:
                self.authorities.clear()
            self.authorities[domain] = authority
        return authority

    async def get_cache(self, domain: bytes, rtype: RType) -> Optional[Answers]:
        """
        Retrieve from cache directly if present
        """
        key = f'{domain}:{rtype.name}'
        async with self.mutex:
            if key not in self.cache:
                return None
            record = self.cache[key]
            if record.is_expired():
                self.logger.debug(f'{key} expired')
                del self.cache[key]
                return None
            return Answers(record.answers.copy(), self.source)

    async def set_cache(self, domain: bytes, rtype: RType, answers: Answers):
        """
        Save the given answers to cache for the specified domain/rtype
        """
        if not answers.answers:
            self.logger.debug(f'cannot cache empty record for {domain!r}')
            return
        key = f'{domain}:{rtype.name}'
        async with self.mutex:
            if len(self.cache) >= self.maxsize:
                self.logger.debug(f'maxsize: {self.maxsize} exceeded. clearing cache!')
                self.cache.clear()
            self.cache[key] = CacheRecord(answers.answers.copy(), self.expiration)

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        Retrieve answers from cache before checking supplied backend
        """
        # attempt to retrieve from cache if it exists
        answers = await self.get_cache(domain, rtype)
        if answers is not None:
            return answers
        # complete standard lookup for answers
        answers = await self.backend.get_answers(domain, rtype)
        if answers.source in self.ignore_sources:
            return answers
        if rtype not in self.ignore_rtypes \
            and all(a.rtype in self.ignore_rtypes for a in answers.answers):
            return answers
        # save results to cache and return results
        if answers is not None and answers.answers:
            await self.set_cache(domain, rtype, answers)
        return answers
