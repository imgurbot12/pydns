"""
In-Memory Backend Implementation
"""
import ipaddress
from typing import Dict, List, Set, Any, ClassVar

from . import Backend, Answers, Answer, RType
from ...answer import get_rclass
from ...content import PTR

#** Variables **#
__all__ = ['MemoryBackend']

#: type definiton for in-memory record database
RecordDB = Dict[bytes, Dict[RType, List[Answer]]]

#: raw record entry configuration
RecordEntries = Dict[str, List[Dict[str, Any]]]

#** Classes **#

class MemoryBackend(Backend):
    """Simple In-Memory Backend for DNS Records"""
    source: ClassVar[str] = 'MemDB'
    
    __slots__ = ('records', 'authorities', 'recursion_available')

    def __init__(self):
        self.records:     RecordDB   = {}
        self.authorities: Set[bytes] = set()

    def add_answer(self, domain: bytes, answer: Answer):
        """
        add additional domain answer into in-memory db
        """
        rtype = answer.rtype
        self.records.setdefault(domain, {})
        self.records[domain].setdefault(rtype, [])
        self.records[domain][rtype].append(answer)
 
    def save_domain(self, domain: bytes, entries: RecordEntries):
        """
        save additional records into in-memory db
        """
        assert isinstance(domain, bytes), 'domain must be bytes'
        # convert dictionary records into valid dns answer objects
        self.authorities.add(domain)
        for rname, records in entries.items():
            rtype  = RType[rname]
            rclass = get_rclass(rtype)
            for record in records:
                # add standard record
                ttl     = record.pop('ttl', 60)
                content = rclass(**record)
                answer  = Answer(domain, ttl, content)
                self.add_answer(domain, answer)
                # reverse ip records for PTR lookups
                ipaddr = record.get('ip', None)
                if ipaddr is not None:
                    ip   = ipaddress.ip_address(ipaddr)
                    name = ip.reverse_pointer.encode()
                    answer = Answer(name, ttl, PTR(domain))
                    self.add_answer(name, answer)

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
