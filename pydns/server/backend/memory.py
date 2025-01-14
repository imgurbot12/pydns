"""
In-Memory Backend Implementation
"""
import ipaddress
from typing import Any, ClassVar, Dict, List, Set, Union
from typing_extensions import TypedDict

from . import Backend, Answers, Answer, RType
from ...answer import get_ctype
from ...content import Content, PTR

#** Variables **#
__all__ = ['MemoryBackend']

#: type definiton for in-memory record database
RecordDB = Dict[bytes, Dict[RType, List[Answer]]]

RecordEntries = List[Union[Content, 'RecordDict']]

RawRecordEntries = Dict[str, List[Dict[str, Any]]]

#** Classes **#

class RecordDict(TypedDict):
    content: Content
    ttl:     int

class MemoryBackend(Backend):
    """
    Simple In-Memory Backend for DNS Records
    """
    source:              ClassVar[str]  = 'MemDB'
    recursion_available: ClassVar[bool] = False #type: ignore

    __slots__ = ('records', 'authorities', 'default_ttl')

    def __init__(self, default_ttl: int = 60):
        self.records:     RecordDB   = {}
        self.authorities: Set[bytes] = set()
        self.default_ttl: int        = default_ttl

    def add_answer(self, domain: bytes, answer: Answer):
        """
        add additional domain answer into in-memory db
        """
        rtype = answer.rtype
        self.records.setdefault(domain, {})
        self.records[domain].setdefault(rtype, [])
        self.records[domain][rtype].append(answer)

    def save_domain(self, domain: bytes, records: RecordEntries):
        """
        save additional records into in-memory db

        :param domain:  dns domain to save records for
        :param records: list of record objects with ttls
        """
        assert isinstance(domain, bytes), 'domain must be bytes'
        # convert dictionary records into valid dns answer objects
        self.authorities.add(domain)
        for record in records:
            # convert record into content and ttl
            if isinstance(record, Content):
                ttl     = self.default_ttl
                content = record
            else:
                ttl     = record.get('ttl', self.default_ttl)
                content = record['content']
            # add standard record
            answer  = Answer(domain, ttl, content)
            self.add_answer(domain, answer)
            # reverse ip records for PTR lookups
            ipaddr = getattr(content, 'ip', None)
            if ipaddr is not None:
                ip   = ipaddress.ip_address(ipaddr)
                name = ip.reverse_pointer.encode()
                answer = Answer(name, ttl, PTR(domain))
                self.add_answer(name, answer)

    def save_domain_dict(self, domain: bytes, entries: RawRecordEntries):
        """
        save additional records into in-memory db using raw dictionary object

        :param domain:  dns domain to save records for
        :param records: list of record objects with ttls
        """
        records = []
        for rname, r_entries in entries.items():
            rtype  = RType[rname]
            ctype  = get_ctype(rtype)
            for entry in r_entries:
                ttl     = entry.pop('ttl', self.default_ttl)
                content = ctype(**entry)
                records.append({'ttl': ttl, 'content': content})
        self.save_domain(domain, records)

    def is_authority(self, domain: bytes) -> bool:
        """
        retrieve if domain is an authority
        """
        return domain in self.authorities

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        retrieve records associated w/ the given domain and record-type
        """
        answers = []
        if domain in self.records:
            records = self.records[domain]
            answers = records.get(rtype, [])
        return Answers(answers, self.source)
