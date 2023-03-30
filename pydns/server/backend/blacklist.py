"""
Backend Domain Blacklist Extension
"""
import os
import re
import dbm
from abc import abstractmethod
from dataclasses import dataclass
from typing import Protocol, Generator, TextIO, ClassVar, Set, Optional

from . import Answers, Backend, RType

#** Variables **#
__all__ = [
    'is_domain',
    'parse_blacklist',

    'BlockDB',
    'DbmBlockDB',

    'Blacklist'
]

#: raw regex expression to match valid web domains
re_expr = r'(?:[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}' + \
    r'[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-_]{0,61}[A-Za-z]\.?'

#: compiled regex expression used to find domains in string
domain_find = re.compile(re_expr, re.IGNORECASE)

#: compiled regex expression to match domains as full-string only
domain_exact = re.compile(f'^{re_expr}$', re.IGNORECASE)

#: type definition for item generating domain names
DomainGenerator = Generator[bytes, None, None]

#** Functions **#

def is_domain(value: str) -> bool:
    """
    return true if given string is a domain
    """
    match = domain_exact.match(value.encode("idna").decode("utf-8"))
    return match is not None

def parse_blacklist(f: TextIO) -> DomainGenerator:
    """
    parse blacklist file to include into blacklist backend
    
    :param f: file-like object to parse domains from
    :return:  iterator to retrieve parsed domains
    """
    skipped = []
    double  = []
    for line in f.readlines():
        # skip commented lines
        if any(line.startswith(c) for c in '!#-/'):
            skipped.append(line)
            continue
        # parse domains, there should only be one per line
        domains = domain_find.findall(line)
        if len(domains) != 1:
            double.append(line)
            continue
        # yield single domains when found
        yield domains[0].encode()

#** Classes **#

class BlockDB(Protocol):
    """
    Abstract Blacklist Database for Extensive Blacklists
    """

    @abstractmethod
    def contains(self, domain: bytes) -> bool:
        raise NotImplementedError

class DbmBlockDB(BlockDB):
    """
    Dbm Key/Value Store Implmenentation for Blacklist Database
    """
    src_key = '__sources'

    def __init__(self, path: str, flag: str = 'cf'):
        self.dbm = dbm.open(path, flag=flag) #type: ignore
        if dbm.whichdb(path) == 'dbm.dumb':
            raise RuntimeError('Python has no valid DBM library installed!')

    def sources(self) -> Set[bytes]:
        """retrieve list of ingested sources"""
        return set(self.dbm.get(self.src_key, b'').split(b','))

    def ingest(self, name: bytes, src: DomainGenerator, validate: bool = True):
        """
        ingest the given source of domain objects

        :param name:     name of source being ingested
        :param src:      source of domains to ingest
        :param validate: validate domains as their being ingested if true
        """
        # write domains one by one into database
        for domain in src:
            if validate and not is_domain(domain.decode()):
                continue
            self.dbm[domain] = b''
        # sync and reorganize data
        if hasattr(self.dbm, 'sync'):
            self.dbm.sync()       #type: ignore
            if hasattr(self.dbm, 'reorganize'):
                self.dbm.reorganize() #type: ignore
        # add source to sources
        sources = self.sources()
        sources.add(name)
        self.dbm[self.src_key] = b','.join(sources)
    
    def ingest_file(self, fpath: str, name: Optional[str] = None):
        """
        ingest domains for the database from the following file
        """
        # only ingest the file if it hasnt been seen before or mtime changed
        name = name or os.path.basename(fpath)
        time = os.path.getmtime(fpath)
        last = float(self.dbm.get(fpath, b'0').decode())
        if time == last:
            return
        # process file and ingest domains and then cache last mtime
        with open(fpath, 'r') as f:
            src = parse_blacklist(f)
            self.ingest(name.encode(), src, validate=False)
            self.dbm[fpath] = str(time).encode()

    def contains(self, domain: bytes) -> bool:
        """check if domain is contained within the dbm key/value store"""
        return domain in self.dbm

@dataclass(repr=False)
class Blacklist(Backend):
    """
    Blacklist Backend Extension. Block all Records for Associated Domains
    """
    __slots__ = ('backend', 'blacklist', 'empty')
    source: ClassVar[str] = 'Blacklist'

    backend:   Backend
    blacklist: Set[bytes]
    database:  Optional[BlockDB] = None
    
    def __post_init__(self):
        self.empty = Answers([], self.source)

    def is_authority(self, domain: bytes) -> bool:
        return self.backend.is_authority(domain)

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """block lookups for blacklisted domains, otherwise do standard query"""
        # check memory cache
        if domain in self.blacklist:
            return self.empty
        # check slower database and move to cache if found
        if self.database and self.database.contains(domain):
            self.blacklist.add(domain)
            return self.empty
        # otherwise do standard backend lookup
        return self.backend.get_answers(domain, rtype)
