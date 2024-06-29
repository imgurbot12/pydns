"""
Simple DBM Database Implementaton for Rule Engine
"""
import re
import os
import dbm
import json
from typing import List, Optional, Set, Tuple

from pydns.server.backend.ruleset.wildcard import WildcardMatch

from . import RuleEngine
from .parser import RuleDef, RuleDefs, Domain, Regex, Status, Wildcard, parse_rules
from .wildcard import WildcardMatch

#** Variables **#
__all__ = ['DbmRuleEngine']

RegexRules = List[Tuple[re.Pattern, Status]]

WildcardRules = List[Tuple[WildcardMatch, Status]]

#** Functions **#

def open_dbm(path: str, flags: str):
    """
    retrieve dbm object and ensure not dbm.dumb

    :param path:  filepath to dbm database
    :param flags: flags to use when loading database
    """
    database = dbm.open(path, flag=flags) #type: ignore
    which    = dbm.whichdb(path)
    if which is None or which == 'dbm.dumb':
        raise RuntimeError('Python has no valid DBM engine installed.')
    return database

def encode_defs(rules: RuleDefs) -> bytes:
    """
    serialize rule definitions as bytes

    :param rules: iterator of rules to serialize
    :return:      serialized rules
    """
    return json.dumps([ruledef.asdict() for ruledef in rules]).encode('latin1')

def decode_defs(ruledefs: Optional[bytes]) -> List[RuleDef]:
    """
    deserialize rule defintions from bytes

    :param ruledefs: serialized rule definitions
    :return:         deserialized rule definitions
    """
    if not ruledefs:
        return []
    return [RuleDef(**rdef) for rdef in json.loads(ruledefs.decode('latin1'))]

#** Classes **#

class DbmRuleEngine(RuleEngine):
    __slots__ = ('dbm', 'regex', 'wildcards')

    source_key:   str = '__sources'
    regex_key:    str = '__%s_regex'
    wildcard_key: str = '__%s_wildcards'
    domain_key:   str = '__%s_domains'

    def _reload_patterns(self):
        """compile regex and wildcard expressions within database"""
        self.regex     = []
        self.wildcards = []
        for source in self.sources():
            regex_key = self.regex_key % source
            for rdef in decode_defs(self.dbm.get(regex_key)):
                rgx = (re.compile(rdef.rule.encode()), rdef.status)
                self.regex.append(rgx)
            wildcard_key = self.wildcard_key %  source
            for rdef in decode_defs(self.dbm.get(wildcard_key)):
                wild = (WildcardMatch.compile(rdef.rule), rdef.status)
                self.wildcards.append(wild)

    def __init__(self, path: str, flag = 'c'):
        self.dbm = open_dbm(path, flag)
        self._reload_patterns()

    def sources(self) -> Set[str]:
        """
        retrieve list of ingested sources
        """
        return set(self.dbm.get(self.source_key, b'').decode().split(','))

    def ingest(self, name: str, rules: RuleDefs):
        """
        ingest incoming source of rule definitions and update database

        :param name:  name of source
        :param rules: rules to ingest
        """
        # separate rules into categories
        domains   = {}
        regex     = []
        wildcards = []
        for ruledef in rules:
            if isinstance(ruledef.rule, Domain):
                domains[ruledef.rule] = 'b' if ruledef.status else 'w'
            elif isinstance(ruledef.rule, Wildcard):
                wildcards.append(ruledef)
            elif isinstance(ruledef.rule, Regex):
                regex.append(ruledef)
        # retrieve related source keys
        regex_key    = self.regex_key % name
        wildcard_key = self.wildcard_key % name
        domain_key   = self.domain_key % name
        # delete previous domain records (if they exist)
        for domain in self.dbm.get(domain_key, b'').split(b','):
            if domain in self.dbm:
                del self.dbm[domain]
        # update sources
        sources = self.sources()
        sources.add(name)
        # write content into dbm at once
        self.dbm[self.source_key] = ','.join(sources).encode()
        self.dbm[domain_key] = b','.join(d.encode() for d in domains.keys())
        self.dbm[regex_key] = encode_defs(regex)
        self.dbm[wildcard_key] = encode_defs(wildcards)
        for domain, rule in domains.items():
            self.dbm[domain] = rule
        # sync and reorganize data (if available)
        if hasattr(self.dbm, 'sync'):
            self.dbm.sync() #type: ignore
        if hasattr(self.dbm, 'reorganize'):
            self.dbm.reorganize() #type: ignore
        # reload regex/wildcard expressions
        self._reload_patterns()

    def ingest_file(self, fpath: str, name: Optional[str] = None):
        """
        parse and ingest ruleset from the specified filepath

        :param fpath: filepath containing rules to add to rule engine
        :param name:  custom name of source for items in db
        """
        # only ingest the file if it hasnt been seen before or mtime changed
        name = name or os.path.basename(fpath)
        time = os.path.getmtime(fpath)
        last = float(self.dbm.get(fpath, b'0').decode())
        if time == last:
            return
        # process file and ingest domains and then cache last mtime
        with open(fpath, 'r') as f:
            rules = parse_rules(f)
            self.ingest(name, rules)
            self.dbm[fpath] = str(time).encode()

    def match_domain(self, domain: bytes) -> Optional[bool]:
        """
        match domain against dbm database of rules

        :param domain: domain to check if in database
        :return:       rule determination (if found)
        """
        rule = self.dbm.get(domain)
        return rule == b'b' if rule is not None else None

    def match_pattern(self, domain: bytes) -> Optional[bool]:
        """
        match domain against existing pattern based rules

        :param domain: domain to check if matching pattern rules
        :return:       rule determination (if matched)
        """
        for wildcard, rule in self.wildcards:
            if wildcard.match(domain):
                return rule
        for regex, rule in self.regex:
            if regex.match(domain):
                return rule
