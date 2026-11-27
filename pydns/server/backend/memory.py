"""
In-Memory Backend Implementation
"""
import ipaddress
from fnmatch import fnmatch
from typing import Any, ClassVar, Dict, List, Optional, Set
from typing_extensions import TypedDict

from . import Backend, Answers, Answer, RType
from ...answer import get_ctype
from ...content import Content, PTR

#** Variables **#
__all__ = ['MemoryBackend']

#: type definition for in-memory record database
RecordDB = Dict[bytes, Dict[RType, List[Answer]]]

RawRecordEntries = Dict[str, List[Dict[str, Any]]]

#** Classes **#

class RecordDict(TypedDict):
    content: Content
    ttl:     int

class MemoryBackend(Backend):
    """
    Simple In-Memory Backend for DNS Records
    """
    source: ClassVar[str] = 'MemDB'

    __slots__ = ('records', 'authorities', 'default_ttl', 'allow_wildcards')

    def __init__(self, default_ttl: int = 60):
        self.records:         RecordDB   = {}
        self.authorities:     Set[bytes] = set()
        self.default_ttl:     int        = default_ttl
        self.allow_wildcards: bool       = False

    def add_answer(self, answer: Answer):
        """
        Add additional domain answer into in-memory db
        """
        rtype = answer.rtype
        self.records.setdefault(answer.name, {})
        self.records[answer.name].setdefault(rtype, [])
        self.records[answer.name][rtype].append(answer)
        self.allow_wildcards = self.allow_wildcards or b'*' in answer.name

    def save_domain(self,
        domain: bytes, content: Content, ttl: Optional[int] = None) -> None:
        """
        Save a record into in-memory db
        """
        assert isinstance(domain, bytes), 'domain must be bytes'
        self.authorities.add(domain)
        ttl    = ttl or self.default_ttl
        answer = Answer(domain, ttl, content)
        self.add_answer(answer)
        # reverse ip records for PTR lookups
        ipaddr = getattr(content, 'ip', None)
        if ipaddr is not None:
            ip   = ipaddress.ip_address(ipaddr)
            name = ip.reverse_pointer.encode()
            answer = Answer(name, ttl, PTR(domain))
            self.add_answer(answer)

    def save_domain_dict(self, domain: bytes, entries: RawRecordEntries):
        """
        Save additional records into in-memory db using raw dictionary object

        :param domain:  dns domain to save records for
        :param records: list of record objects with ttls
        """
        for rname, r_entries in entries.items():
            rtype  = RType[rname]
            ctype  = get_ctype(rtype)
            for entry in r_entries:
                ttl     = entry.pop('ttl', self.default_ttl)
                content = ctype(**entry)
                self.save_domain(domain, content, ttl)

    def recursion_available(self) -> bool:
        return False

    async def is_authority(self, domain: bytes) -> bool:
        """
        Retrieve if domain is an authority
        """
        return domain in self.authorities

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        Retrieve records associated with the given domain and record-type
        """
        answers = []
        if domain in self.records:
            records = self.records[domain]
            answers = records.get(rtype, [])
        elif self.allow_wildcards:
            wildcards = [(k,r) for k,r in self.records.items() if b'*' in k]
            wildcards.sort(key=lambda item: len(item[0]), reverse=True)
            for key, records in wildcards:
                if fnmatch(domain, key):
                    answers = records.get(rtype, []).copy()
                    for answer in answers:
                        answer.name = domain
                    break;
        return Answers(answers, self.source)
