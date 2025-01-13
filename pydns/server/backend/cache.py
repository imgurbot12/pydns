"""
Backend Extension to support In-Memory Answer Caching
"""
import time
import math
from logging import Logger, getLogger
from threading import Lock
from typing import ClassVar, Dict, List, Optional, Set

from pyderive import InitVar, dataclass, field

from . import Answers, Backend, RType, Answer
from .memory import MemoryBackend
from .ruleset import RuleBackend

#** Variables **#
__all__ = ['Cache']

#: default set of other backend sources to ignore
IGNORE = {MemoryBackend.source, RuleBackend.source}

#** Classes **#

@dataclass(slots=True)
class CacheRecord:
    """
    Record Entry for In-Memory Cache
    """
    answers:    List[Answer]
    expiration: InitVar[int]
    expires:    float = field(init=False)
    accessed:   float = field(init=False)

    def __post_init__(self, expiration: int): #type: ignore
        """
        calculate expiration-time and last-accessed time
        """
        ttl = min(a.ttl for a in self.answers)
        ttl = min(ttl, expiration) if expiration else ttl
        now = time.time()
        self.expires  = now + ttl
        self.accessed = now

    def is_expired(self) -> bool:
        """
        calculate if expiration has passed or ttl is expired
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

@dataclass(slots=True, repr=False)
class Cache(Backend):
    """
    In-Memory Cache Extension for Backend Results
    """
    source: ClassVar[str] = 'Cache'

    backend:        Backend
    expiration:     int        = 30
    maxsize:        int        = 10000
    ignore_rtypes:  Set[RType] = field(default_factory=lambda: {RType.SOA, })
    ignore_sources: Set[str]   = field(default_factory=lambda: IGNORE)
    logger:         Logger     = field(default_factory=lambda: getLogger('pydns'))

    mutex:       Lock                   = field(default_factory=Lock, init=False)
    cache:       Dict[str, CacheRecord] = field(default_factory=dict, init=False)
    authorities: Dict[bytes, bool]      = field(default_factory=dict, init=False)

    recursion_available: bool = field(default=False, init=False)

    def __post_init__(self):
        self.logger              = self.logger.getChild('cache')
        self.recursion_available = self.backend.recursion_available

    def is_authority(self, domain: bytes) -> bool:
        """
        retrieve if domain is authority from cache before checking backend
        """
        # check cache before querying backend
        if domain in self.authorities:
            return self.authorities[domain]
        # query backend and then permanently cache authority result
        authority = self.backend.is_authority(domain)
        with self.mutex:
            if len(self.authorities) >= self.maxsize:
                self.authorities.clear()
            self.authorities[domain] = authority
        return authority

    def get_cache(self, domain: bytes, rtype: RType) -> Optional[Answers]:
        """
        retrieve from cache directly if present
        """
        key = f'{domain}->{rtype.name}'
        with self.mutex:
            if key not in self.cache:
                return
            record = self.cache[key]
            if record.is_expired():
                self.logger.debug(f'{key} expired')
                del self.cache[key]
                return
            return Answers(record.answers, self.source)

    def set_cache(self, domain: bytes, rtype: RType, answers: Answers):
        """
        save the given answers to cache for the specified domain/rtype
        """
        if not answers.answers:
            self.logger.debug(f'cannot cache empty record for {domain!r}')
            return
        key = f'{domain}->{rtype.name}'
        with self.mutex:
            if len(self.cache) >= self.maxsize:
                self.logger.debug(f'maxsize: {self.maxsize} exceeded. clearing cache!')
                self.cache.clear()
            self.cache[key] = CacheRecord(answers.answers, self.expiration)

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        retrieve answers from cache before checking supplied backend
        """
        # attempt to retrieve from cache if it exists
        answers = self.get_cache(domain, rtype)
        if answers is not None:
            return answers
        # complete standard lookup for answers
        answers = self.backend.get_answers(domain, rtype)
        if answers.source in self.ignore_sources:
            return answers
        if rtype not in self.ignore_rtypes \
            and all(a.rtype in self.ignore_rtypes for a in answers.answers):
            return answers
        # save results to cache and return results
        self.set_cache(domain, rtype, answers)
        return answers
