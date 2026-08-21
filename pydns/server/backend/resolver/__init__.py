"""
Recursive Manual DNS Resolver
"""
import math
import random
from abc import abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Generic, List, Optional, Protocol, TypeVar

from pyderive import dataclass

from .... import Answer, Content, NS, Question, RType
from ....client import UdpClient

#** Variables **#
__all__ = [
    'Record',
    'ResolverCache',
]

C = TypeVar('C', bound=Content)

ROOT_SERVERS = [
    'a.root-servers.net',
    'b.root-servers.net',
    'c.root-servers.net',
    'd.root-servers.net',
    'e.root-servers.net',
    'f.root-servers.net',
    'g.root-servers.net',
    'h.root-servers.net',
    'i.root-servers.net',
    'j.root-servers.net',
    'k.root-servers.net',
    'l.root-servers.net',
    'm.root-servers.net',
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

class Resolver:
    """
    """
    __slots__ = ('servers', 'client', 'cache')

    servers: List[str]
    cache:   ResolverCache

    def __init__(self,
        root_servers: List[str]               = ROOT_SERVERS,
        cache:        Optional[ResolverCache] = None,
    ):
        self.servers = root_servers
        self.client  = UdpClient([])
        self.cache   = cache or SqliteResolverCache('./rcache.db')

    def get_closest_ns(self, domain: bytes) -> str:
        """
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
            return ns.content.nameserver.decode()
        return random.choice(self.servers)

    def resolve(self, domain: bytes, rtype: RType) -> Optional[List[Answer]]:
        """
        """
        answers = self.cache.get(domain, rtype)
        if answers:
            now = datetime.now()
            return [r.to_answer(domain, now) for r in answers]

        server   = self.get_closest_ns(domain)
        question = Question(domain, rtype)
        message  = self.client._build_query(question)
        while True:
            addr = (server, 53)
            res  = self.client.request(message, addr=addr)
            res.raise_on_error()

            valid       = []
            servers     = []
            raw_answers = res.answers + res.authority + res.additional
            answers     = [a for a in raw_answers if isinstance(a, Answer)]
            self.cache.put_answers(answers)
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

#** Init **#
from .sqlite import SqliteResolverCache
