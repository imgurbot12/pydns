"""
Recursive Manual DNS Resolver
"""
import math
import random
from abc import abstractmethod
from datetime import datetime, timedelta
import socket
from typing import (
    ClassVar, Dict, Generic, List, Optional, Protocol, TypeVar, Union, cast)
from typing_extensions import deprecated

from pyderive import dataclass

from .. import Answers, Backend
from .... import A, AAAA, NS, Answer, Content, Question, RType
from ....client import UdpClient, build_request
from ....content import CNAME, Unknown
from ....exceptions import DnsError
from ....message import Message

#** Variables **#
__all__ = [
    'Record',
    'ResolverCache',
]

C = TypeVar('C', bound=Union[Content, Unknown])

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
        return Answer(domain, ttl, cast(Content, self.content))

class ResolverCache(Protocol):
    """
    Resolver Cache Abstraction
    """

    @abstractmethod
    async def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        raise NotImplementedError

    @abstractmethod
    async def put(self, domain: bytes, rtype: RType, records: List[Record]):
        raise NotImplementedError

    async def put_answers(self, answers: List[Answer]):
        """
        Batch all answers to be cached into list of associated record-types
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
                await self.put(domain, rtype, recs)

class MemoryCache(ResolverCache):
    """
    Basic In-Memory Cache for Resolver
    """
    __slots__ = ('cache', )

    cache: Dict[bytes, Dict[RType, List[Record]]]

    def __init__(self):
        self.cache = {}

    async def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        cache = self.cache.get(domain, None)
        if not cache:
            return None
        records = cache.get(rtype, None)
        if records is None:
            return None
        now     = datetime.now()
        records = [r for r in records if r.expiration > now]
        if not records:
            cache.pop(rtype, None)
            return None
        cache[rtype] = records
        return records

    async def put(self, domain: bytes, rtype: RType, records: List[Record]):
        self.cache.setdefault(domain, {})
        self.cache[domain].setdefault(rtype, [])
        self.cache[domain][rtype].extend(records)

#TODO: port resolver to full async using UdpAsyncClient rather than socket

@deprecated('Highly experimental. Use at own risk.')
class Resolver(Backend):
    """
    Recursive Manual DNS Resolution Backend

    This Backend recursively searches for a specific record from the root
    domain servers which avoids relying on third-party DNS servers to complete
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
        client:       Optional[UdpClient]     = None,
    ):
        self.backend = backend
        self.client  = client or UdpClient([], pool_size=0)
        self.cache   = cache or ResolverCacheDB('./rcache.db')
        self.servers = root_servers

    def recursion_available(self) -> bool:
        return True

    async def get_closest_ns(self, domain: bytes) -> bytes:
        """
        get closest associated nameserver with the given domain

        :param domain: domain to get associated nameserver for
        :return:       closest associated nameserver
        """
        segments = domain.split(b'.')
        domains  = (b'.'.join(segments[n:]) for n in range(0, len(segments)))
        servers  = None #type: Optional[List[Record[NS]]]
        for segment in domains:
            servers = await self.cache.get(segment, RType.NS)
            if servers is not None:
                break
        if servers:
            ns = random.choice(servers)
            return ns.content.nameserver
        return random.choice(self.servers)

    async def get_host(self, domain: bytes) -> str:
        """
        retrieve host address associated with domain before connecting

        :param domain: specified domain to resolve
        :return:       resolved host address for domain
        """
        ipv4: Optional[List[Record[A]]] = await self.cache.get(domain, RType.A)
        if ipv4:
            ips = [str(r.content.ip) for r in ipv4]
            return random.choice(ips)
        ipv6: Optional[List[Record[AAAA]]] = await self.cache.get(domain, RType.AAAA)
        if ipv6:
            ips = [str(r.content.ip) for r in ipv6]
            return random.choice(ips)
        return domain.decode()

    async def resolve(self, domain: bytes, rtype: RType) -> Optional[List[Answer]]:
        """
        lookup the associated record with recursive lookup

        :param domain: domain to lookup
        :param rtype:  record type to retrieve for domain
        :return:       list of associated answers (if found)
        """
        answers = await self.cache.get(domain, rtype)
        if answers:
            now = datetime.now()
            return [r.to_answer(domain, now) for r in answers]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        names    = []
        server   = await self.get_closest_ns(domain)
        question = Question(domain, rtype)
        message  = build_request(question)
        while True:
            host = await self.get_host(server)
            addr = (host, 53)

            sock.sendto(message.pack(), addr)
            data, _ = sock.recvfrom(8192)
            res     = Message.unpack(data, source=addr[0])
            res.raise_on_error()

            raw_answers = res.answers + res.authority + res.additional
            filtered    = [a for a in raw_answers if isinstance(a, Answer)]
            await self.cache.put_answers(filtered)

            valid   = []
            servers = []
            for ans in filtered:
                if ans.name == domain or any(a.name == domain for a in names):
                    if ans.rtype == rtype:
                        valid.extend(names)
                        valid.append(ans)
                    if isinstance(ans.content, CNAME):
                        names.append(ans)
                if isinstance(ans.content, NS):
                    servers.append(ans.content.nameserver)

            if valid:
                return valid
            if not servers:
                break
            server = random.choice(servers)

        sock.close()
        if names:
            domain  = names[-1].content.name
            records = await self.resolve(domain, rtype)
            if records is not None:
                records.insert(0, names[-1])
                return records
        return None

    async def is_authority(self, domain: bytes) -> bool:
        if self.backend is not None:
            return await self.backend.is_authority(domain)
        return False

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        if self.backend is not None:
            answers = await self.backend.get_answers(domain, rtype)
            if answers.answers or answers.rcode is not None:
                return answers
        try:
            r_answers = await self.resolve(domain, rtype)
        except DnsError as err:
            return Answers([], self.source, rcode=err.rcode)
        return Answers(r_answers or [], self.source)

#** Init **#
from .database import ResolverCacheDB
