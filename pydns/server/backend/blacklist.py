"""
Backend Domain Blacklist Extension
"""
import os
import re
import dbm
import enum
from abc import abstractmethod
from typing import List, NamedTuple, Protocol, Generator, TextIO, ClassVar, Set, Optional

from pyderive import dataclass

from . import Answers, Backend, RType

#** Variables **#
__all__ = [
    'is_domain',
    'list_domains',
    'parse_ruleset',

    'DomainRule',
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
RuleGenerator = Generator['DomainRule', None, None]

#** Functions **#

def ignore_line(line: str) -> bool:
    """
    determine if blocklist file line should be ignored

    :param line: line from file instance
    :return:     true if line should be ignored
    """
    # ignore adguard path/rule specific blocks
    if '/' in line or '#' in line or line.startswith('^'):
        return True
    if line.startswith('||') and not line.endswith('^'):
        return True
    return False

def is_domain(value: str) -> bool:
    """
    return true if given string is a domain
    """
    match = domain_exact.match(value.encode("idna").decode("utf-8"))
    return match is not None

def find_domain(line: str) -> Optional[str]:
    """
    attempt to find domain in single line of blocklist code

    :param line: line of blocklist potentially containing a domain to block
    :return:     domain found in line
    """
    # skip commented lines
    line = line.strip()
    if any(line.startswith(c) for c in '!#-/'):
        return
    # skip lines with multiple potential domains or ignored lines
    domains = domain_find.findall(line)
    if len(domains) != 1 or ignore_line(line):
        return
    return domains[0]

def list_domains(text: str) -> List[str]:
    """
    retrieve domains contained within text

    :param text: text potentially containing domains
    :return:     list of domains found in text
    """
    domains = []
    for line in text.splitlines():
        domain = find_domain(line)
        if domain:
            domains.append(domain)
    return domains

def parse_ruleset(f: TextIO) -> RuleGenerator:
    """
    parse ruleset file to include into whitelist/blacklist backend

    :param f: file-like object to parse domains from
    :return:  iterator to retrieve parsed domains
    """
    for line in f.readlines():
        line   = line.strip()
        domain = find_domain(line)
        if not domain:
            continue
        if line.startswith('@@'):
            yield DomainRule(RuleStatus.WHITELIST, domain.encode())
        else:
            yield DomainRule(RuleStatus.BLACKLIST, domain.encode())

def split_domains(domain: bytes) -> List[bytes]:
    """
    split base-domain into all possible subdomains
    example: www.example.com => [www.example.com, example.com]

    :param domain: domain to be split into items
    :return:       split domain list
    """
    domains = []
    while domain.count(b'.') > 0:
        domains.append(domain)
        _, domain = domain.split(b'.', 1)
    return domains

#** Classes **#

class RuleStatus(enum.Enum):
    """
    Declaration of Domain Match Status
    """
    WHITELIST = False
    BLACKLIST = True

class DomainRule(NamedTuple):
    """
    Parsed Rule from RuleSet
    """
    status: RuleStatus
    domain: bytes

class BlockDB(Protocol):
    """
    Abstract Blacklist Database for Extensive Blacklists
    """

    @abstractmethod
    def match_exact(self, domain: bytes) -> Optional[bool]:
        raise NotImplementedError

    def match(self, domain: bytes) -> Optional[bool]:
        """
        check if domain is contained within the database

        :param domain: domain to check if in db
        :return:       true if domain in db
        """
        for match in split_domains(domain):
            rule = self.match_exact(match)
            if rule is not None:
                return rule

class DbmBlockDB(BlockDB):
    """
    Dbm Key/Value Store Implmenentation for Blacklist Database
    """
    src_key = '__sources'

    def __init__(self, path: str, flag = 'c'):
        self.dbm = dbm.open(path, flag=flag) #type: ignore
        which = dbm.whichdb(path)
        if which is None or which == 'dbm.dumb':
            raise RuntimeError('Python has no valid DBM library installed!')

    def sources(self) -> Set[bytes]:
        """retrieve list of ingested sources"""
        return set(self.dbm.get(self.src_key, b'').split(b','))

    def ingest(self, name: bytes, src: RuleGenerator, validate: bool = True):
        """
        ingest the given source of domain objects

        :param name:     name of source being ingested
        :param src:      source of domains to ingest
        :param validate: validate domains as their being ingested if true
        """
        # write domains one by one into database
        for rule in src:
            if validate and not is_domain(rule.domain.decode()):
                continue
            self.dbm[rule.domain] = 'b' if rule.status.value is True else 'w'
        # sync and reorganize data
        if hasattr(self.dbm, 'sync'):
            self.dbm.sync() #type: ignore
        if hasattr(self.dbm, 'reorganize'):
            self.dbm.reorganize() #type: ignore
        # add source to sources
        sources = self.sources()
        sources.add(name)
        self.dbm[self.src_key] = b','.join(sources)

    def ingest_file(self, fpath: str, name: Optional[str] = None):
        """
        ingest domains for the database from the following file

        :param fpath: filepath to add to the blacklist-db
        :param name:  set name of source for the given filepath
        """
        # only ingest the file if it hasnt been seen before or mtime changed
        name = name or os.path.basename(fpath)
        time = os.path.getmtime(fpath)
        last = float(self.dbm.get(fpath, b'0').decode())
        if time == last:
            return
        # process file and ingest domains and then cache last mtime
        with open(fpath, 'r') as f:
            src = parse_ruleset(f)
            self.ingest(name.encode(), src, validate=False)
            self.dbm[fpath] = str(time).encode()

    def match_exact(self, domain: bytes) -> Optional[bool]:
        """
        check if exact-domain is contained within the dbm key/value store

        :param domain: domain to check if in db
        :return:       true if domain in db
        """
        match = self.dbm.get(domain)
        return match == b'b' if match is not None else None

    def add(self, domain: DomainRule):
        """
        add the specified domain to the db

        :param domain: domain to add to the blacklist
        """
        self.ingest(b'_manual', (d for d in (domain, )))

    def remove(self, domain: bytes) -> bool:
        """
        remove the specified domain from the db

        :param domain: domain to remove from the blacklist
        :return:       true if domain was present and removed
        """
        if domain in self.dbm:
            del self.dbm[domain]
            return True
        return False

@dataclass(slots=True, repr=False)
class Blacklist(Backend):
    """
    Blacklist Backend Extension. Block all Records for Associated Domains
    """
    source: ClassVar[str] = 'Blacklist'

    backend:   Backend
    blacklist: Set[bytes]
    whitelist: Set[bytes]
    database:  Optional[BlockDB] = None

    def __post_init__(self):
        self.recursion_available = self.backend.recursion_available
        self.empty = Answers([], self.source)
        self.blacklist -= self.whitelist

    def is_authority(self, domain: bytes) -> bool:
        """
        :param domain: check if domain is authority
        :return:       true if backend has authority over domain
        """
        return self.backend.is_authority(domain)

    def is_blocked(self, domain: bytes) -> bool:
        """
        check if the following domain is blocked

        :param domain: domain to check if blocked
        :return:       true if domain is blocked else false
        """
        # check if domain in in-memory whitelist of blacklist
        domains = split_domains(domain)
        if any(match in self.whitelist for match in domains):
            return False
        if any(match in self.blacklist for match in domains):
            return True
        # check if record in database
        if self.database:
            for match in domains:
                matches = self.database.match_exact(match)
                if matches is True:
                    self.blacklist.add(domain)
                    self.blacklist.add(match)
                    return True
                if matches is False:
                    self.whitelist.add(domain)
                    self.whitelist.add(match)
                    return False
        return False

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        block lookups for blacklisted domains, otherwise do standard query

        :param domain: domain to check if blocked or return results
        :param rtype:  record-type associated w/ query
        :return:       empty-answers (if blocked), else standard search results
        """
        if self.is_blocked(domain):
            return self.empty
        return self.backend.get_answers(domain, rtype)
