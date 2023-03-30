"""
Backend Extension to support In-Memory Answer Caching
"""
import time
import math
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, ClassVar

from . import Answers, Backend, RType, Answer
from .memory import MemoryBackend
from .blacklist import Blacklist

#** Variables **#
__all__ = ['Cache']

#: default set of other backend sources to ignore
IGNORE = {MemoryBackend.source, Blacklist.source}

#** Classes **#

@dataclass
class CacheRecord:
    """
    Record Entry for In-Memory Cache
    """
    __slots__ = ('answers', 'expiration', 'ttl', 'lifetime_mod')

    answers:    List[Answer]
    expiration: float
    ttl:        int

    def __post_init__(self):
        self.lifetime_mod = 0

    def lifetime(self):
        """calculate lifetime remaining of record"""
        return int(math.floor(self.expiration - time.time()))

    def ttl_mod(self, lifetime: int) -> int:
        """calculate ttl modifier based on the given lifetime"""
        elapsed = self.ttl - lifetime
        ttl_mod = elapsed - self.lifetime_mod
        self.lifetime_mod = elapsed
        return ttl_mod

@dataclass(repr=False)
class Cache(Backend):
    """
    In-Memory Cache Extension for Backend Results
    """
    source: ClassVar[str] = 'Cache'
    __slots__ = (
        'recursion_available',

        'backend', 
        'mutex', 
        'authorities', 
        'cache', 
    )

    backend:    Backend
    expiration: int = 30
    maxsize:    int = 10000
    ignore:     Set[str] = field(default_factory=lambda: IGNORE)

    def __post_init__(self):
        self.recursion_available = self.backend.recursion_available
        self.mutex = threading.Lock()
        self.authorities: Dict[bytes, bool]      = {}
        self.cache:       Dict[str, CacheRecord] = {}

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

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        retrieve answers from cache before checking supplied backend
        """
        # attempt to retrieve from cache if it exists
        key     = f'{domain}->{rtype.name}'
        answers = None
        if key in self.cache:
            with self.mutex:
                record   = self.cache[key]
                lifetime = record.lifetime()
                if lifetime > 0:
                    # modify answer TTLs as cache begins to expire
                    expire  = False
                    ttl_mod = record.ttl_mod(lifetime)
                    for answer in record.answers:
                        answer.ttl -= ttl_mod
                        if answer.ttl <= 0:
                            expire = True
                    # only return answers if none are expired
                    if not expire:
                        return Answers(record.answers, self.source)
                del self.cache[key]
        # complete standard lookup for answers
        answers = self.backend.get_answers(domain, rtype)
        if answers.source in self.ignore:
            return answers
        # cache result w/ optional expiration and return results
        answers, source = answers
        ttl        = max(a.ttl for a in answers) if answers else self.expiration
        ttl        = min(ttl, self.expiration)
        expiration = time.time() + ttl
        with self.mutex:
            if len(self.cache) >= self.maxsize:
                self.cache.clear()
            self.cache[key] = CacheRecord(answers, expiration, ttl)
        return Answers(answers, source)

