import time
import math
import threading
from abc import abstractmethod
from dataclasses import dataclass
from typing import NamedTuple, Protocol, List, Dict

from ...enum import RType
from ...answer import Answer
from ...client import BaseClient
from ...question import Question

#** Variables **#
__all__ = ['Backend', 'Forwarder', 'Cache', 'MemoryBackend']

#** Classes **#

class Answers(NamedTuple):
    """custom return type when retrieving backend answers"""
    answers: List[Answer]
    source:  str

class Backend(Protocol):
    """
    BaseClass Interface Definition for Backend Implementations
    """
    recursion_available: bool = False

    @abstractmethod
    def is_authority(self, domain: bytes) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        raise NotImplementedError

@dataclass(repr=False)
class Forwarder(Backend):
    """
    Recursive Dns-Client Lookup Forwarder when Backend returns no Results
    """
    __slots__ = ('backend', 'client', 'recursion_available')

    backend: Backend
    client:  BaseClient
    
    def __post_init__(self):
        self.recursion_available = True

    def is_authority(self, domain: bytes) -> bool:
        return self.backend.is_authority(domain)

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        query for answers w/ client if base-backend returns empty result
        """
        answers, source = self.backend.get_answers(domain, rtype)
        if not answers:
            source  = self.__class__.__name__
            message = self.client.query(Question(domain, rtype))
            answers.extend(message.answers)
            answers.extend(message.authority)
            answers.extend([
                a for a in message.additional if isinstance(a, Answer)])
        return Answers(answers, source)

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
    backend:    Backend
    expiration: int = 30
    maxsize:    int = 10000

    def __post_init__(self):
        self.recursion_available = self.backend.recursion_available
        self.mutex = threading.Lock()
        self.authorities: Dict[bytes, bool]      = {}
        self.cache:       Dict[str, CacheRecord] = {}
        self.source:      str                    = self.__class__.__name__

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
        answers, source = self.backend.get_answers(domain, rtype)
        ttl        = max(a.ttl for a in answers) if answers else self.expiration
        ttl        = min(ttl, self.expiration)
        expiration = time.time() + ttl
        # cache result w/ optional expiration and return results
        with self.mutex:
            if len(self.cache) >= self.maxsize:
                self.cache.clear()
            self.cache[key] = CacheRecord(answers, expiration, ttl)
        return Answers(answers, source)

#** Imports **#
from .memory import MemoryBackend
