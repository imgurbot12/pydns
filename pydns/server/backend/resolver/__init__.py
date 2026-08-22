"""
Recursive Manual DNS Resolver
"""
import math
import random
from abc import abstractmethod
from datetime import datetime, timedelta
from typing import ClassVar, Dict, Generic, List, Optional, Protocol, TypeVar

from pyderive import dataclass

from .. import Answers, Backend
from .... import A, AAAA, NS, Answer, Content, Question, RType
from ....client import UdpClient, build_request

#** Variables **#
__all__ = [
    'Record',
    'ResolverCache',
]

C = TypeVar('C', bound=Content)

ROOT_SERVERS = [
    b'a.root-servers.net',
    b'b.root-servers.net',
    b'c.root-servers.net',
    b'd.root-servers.net',
    b'e.root-servers.net',
    b'f.root-servers.net',
    b'g.root-servers.net',
    b'h.root-servers.net',
    b'i.root-servers.net',
    b'j.root-servers.net',
    b'k.root-servers.net',
    b'l.root-servers.net',
    b'm.root-servers.net',
]

#** Classes **#

@dataclass(slots=True)
class Record(Generic[C]):
    content:    C
    expiration: datetime

    def to_answer(self, domain: bytes, now: datetime) -> Answer:
        """
        """
        ttl = math.floor((self.expiration - now).total_seconds())
        return Answer(domain, ttl, self.content)

class ResolverCache(Protocol):
    """
    Resolver Cache Abstraction
    """

    @abstractmethod
    def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        raise NotImplementedError

    @abstractmethod
    def put(self, domain: bytes, rtype: RType, records: List[Record]):
        raise NotImplementedError

    def put_answers(self, answers: List[Answer]):
        """
        batch all answers to be cached into list of associated record-types

        :param answers: list of answers to save within cache
        """
        now = datetime.now()
        records: Dict[bytes, Dict[RType, List[Record]]] = {}
        for answer in answers:
            expr   = now + timedelta(seconds=answer.ttl)
            record = Record(answer.content, expr)
            records.setdefault(answer.name, {})
            records[answer.name].setdefault(answer.content.rtype, [])
            records[answer.name][answer.content.rtype].append(record)
        for domain, cache in records.items():
            for rtype, recs in cache.items():
                self.put(domain, rtype, recs)

class MemoryCache(ResolverCache):
    """
    Basic In-Memory Cache for Resolver
    """
    __slots__ = ('cache', )

    def __init__(self):
        self.cache: Dict[bytes, Dict[RType, List[Record]]] = {}

    def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        cache = self.cache.get(domain, None)
        if not cache:
            return
        records = cache.get(rtype, None)
        if records is None:
            return
        now     = datetime.now()
        records = [r for r in records if r.expiration > now]
        if not records:
            cache.pop(rtype, None)
            return
        cache[rtype] = records
        return records

    def put(self, domain: bytes, rtype: RType, records: List[Record]):
        self.cache.setdefault(domain, {})
        self.cache[domain].setdefault(rtype, [])
        self.cache[domain][rtype].extend(records)

class Resolver(Backend):
    """
    Recursive Manual DNS Resolution Backend

    This Backend recursively searches for a specific record from the root
    domain servers which avoids relying on third-party dns servers to complete
    the search on the client's behalf.
    """
    __slots__ = ('backend', 'cache', 'client', 'servers', )

    source: ClassVar[str] = 'Resolver'

    backend: Optional[Backend]
    cache:   ResolverCache
    servers: List[bytes]

    def __init__(self,
        backend:      Optional[Backend]       = None,
        root_servers: List[bytes]             = ROOT_SERVERS,
        cache:        Optional[ResolverCache] = None,
    ):
        self.backend = backend
        self.client  = UdpClient([])
        self.cache   = cache or SqliteResolverCache('./rcache.db')
        self.servers = root_servers

    def get_closest_ns(self, domain: bytes) -> bytes:
        """
        get closest associated nameserver with the given domain

        :param domain: domain to get associated nameserver for
        :return:       closest associated nameserver
        """
        segments = domain.split(b'.')
        domains  = (b'.'.join(segments[n:]) for n in range(0, len(segments)))
        servers  = None #type: Optional[List[Record[NS]]]
        for segment in domains:
            servers = self.cache.get(segment, RType.NS)
            if servers is not None:
                break
        if servers:
            ns = random.choice(servers)
            return ns.content.nameserver
        return random.choice(self.servers)

    def get_host(self, domain: bytes) -> str:
        """
        retrieve host address associated with domain before connecting

        :param domain: specified domain to resolve
        :return:       resolved host address for domain
        """
        ipv4: Optional[List[Record[A]]] = self.cache.get(domain, RType.A)
        if ipv4:
            ips = [str(r.content.ip) for r in ipv4]
            return random.choice(ips)
        ipv6: Optional[List[Record[AAAA]]] = self.cache.get(domain, RType.AAAA)
        if ipv6:
            ips = [str(r.content.ip) for r in ipv6]
            return random.choice(ips)
        return domain.decode()

    def resolve(self, domain: bytes, rtype: RType) -> Optional[List[Answer]]:
        """
        lookup the associated record with recursive lookup

        :param domain: domain to lookup
        :param rtype:  record type to retrieve for domain
        :return:       list of associated answers (if found)
        """
        answers = self.cache.get(domain, rtype)
        if answers:
            now = datetime.now()
            return [r.to_answer(domain, now) for r in answers]

        server   = self.get_closest_ns(domain)
        question = Question(domain, rtype)
        message  = build_request(question)
        while True:
            host = self.get_host(server)
            addr = (host, 53)
            res  = self.client.request(message, addr=addr)
            res.raise_on_error()

            raw_answers = res.answers + res.authority + res.additional
            answers     = [a for a in raw_answers if isinstance(a, Answer)]
            self.cache.put_answers(answers)

            valid   = []
            servers = []
            for answer in answers:
                if answer.name == domain and answer.content.rtype == rtype:
                    valid.append(answer)
                if isinstance(answer.content, NS):
                    servers.append(answer.content.nameserver)

            if valid:
                return valid
            if not servers:
                break
            server = random.choice(servers)

    def is_authority(self, domain: bytes) -> bool:
        if self.backend is not None:
            return self.backend.is_authority(domain)
        return False

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        if self.backend is not None:
            answers = self.backend.get_answers(domain, rtype)
            if answers.answers or answers.rcode is not None:
                return answers
        r_answers = self.resolve(domain, rtype)
        return Answers(r_answers or [], self.source)

#** Init **#
from .sqlite import SqliteResolverCache
