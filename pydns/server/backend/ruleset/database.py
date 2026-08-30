"""
Simple Sqlite3 Database Implementaton for Rule Engine
"""
import os
import re
from io import StringIO
from datetime import datetime
from typing import List, Optional

from . import RuleEngine, RStatus
from .parser import RuleDefs, Domain, Regex, Wildcard, parse_rules
from .wildcard import WildcardMatch
from .._sql import ruleset_db

#** Variables **#
__all__ = ['RuleEngineDB']

#** Classes **#

class RuleEngineDB(RuleEngine):
    """
    Simple Sqlite3 Supported Rule Engine for RuleBackend
    """
    __slots__ = ('conn',
        'regex_allow', 'regex_block' 'wildcard_allow', 'wildcard_block')

    regex_allow:    List[re.Pattern]
    regex_block:    List[re.Pattern]
    wildcard_allow: List[WildcardMatch]
    wildcard_block: List[WildcardMatch]

    def __init__(self, path: str, sync: bool = True):
        self.conn = ruleset_db(path)
        if sync is True:
            self.sync()

    def _create_source(self, name: str,
        path: Optional[str], date: Optional[datetime]) -> int:
        """
        create a new source record with a unique id
        """
        date = date or datetime.now()
        rec  = self.conn.fetch_one('SELECT MAX(SourceId)+1 FROM Sources')
        sid  = (rec[0] if rec else 1) or 1
        sql  = 'INSERT INTO Sources VALUES (%s, %s, %s, %s)'
        self.conn.execute(sql, (sid, name, path, date.isoformat()))
        return sid

    def _update_source(self, sid: int) -> int:
        """
        update the last-updated datetime tracker for the specific source
        """
        sql = "UPDATE Sources SET LastUpdated=datetime('now') WHERE SourceId=?"
        self.conn.execute(sql, (sid, ))
        return sid

    def _delete_source(self, sid: int):
        """
        delete all patterns and domains associated with a specific source
        """
        args = (sid, )
        for stmt in (
            'DELETE FROM RegexPatterns WHERE SourceId=?',
            'DELETE FROM WildcardPatterns WHERE SourceId=?',
            'DELETE FROM Domains WHERE SourceId=?',
        ):
            self.conn.execute(stmt, args)

    def _ingest(self, sid: int, rules: RuleDefs):
        """
        add all of the given rules to the specified source
        """
        domains   = []
        regex     = []
        wildcards = []
        for rdef in rules:
            if isinstance(rdef.rule, Domain):
                domains.append((sid, str(rdef.rule), rdef.status.value))
            elif isinstance(rdef.rule, Wildcard):
                wildcards.append((sid, str(rdef.rule), rdef.status.value))
            elif isinstance(rdef.rule, Regex):
                regex.append((sid, str(rdef.rule), rdef.status.value))
        self.conn.execute_many(
            'INSERT INTO RegexPatterns VALUES (%s, %s, %s)', regex)
        self.conn.execute_many(
            'INSERT INTO WildcardPatterns VALUES (%s, %s, %s)', wildcards)
        self.conn.execute_many(
            'INSERT INTO Domains VALUES (%s, %s, %s)', domains)

    def sync(self):
        """
        compile regex and wildcard expressions within database
        """
        sql_regex    = 'SELECT Pattern,Rule FROM RegexPatterns'
        sql_wildcard = 'SELECT Pattern,Rule FROM WildcardPatterns'
        self.regex_allow    = []
        self.regex_block    = []
        self.wildcard_allow = []
        self.wildcard_block = []
        for row in self.conn.fetch_yield(sql_regex):
            (pattern, status) = row
            store = self.regex_allow \
                if status == RStatus.WHITELIST else self.regex_block
            store.append(re.compile(pattern))
        for row in self.conn.fetch_yield(sql_wildcard):
            (pattern, status) = row
            store = self.wildcard_allow \
                if status == RStatus.WHITELIST else self.wildcard_block
            store.append(WildcardMatch.compile(pattern))

    def ingest(self, name: str, rules: RuleDefs, sync: bool = True):
        """
        ingest incoming source of rule definitions and update database

        :param name:  name of source
        :param rules: rules to ingest
        :param sync:  sync database after ingestion
        """
        rec = self.conn.fetch_one(
            'SELECT SourceId FROM Sources WHERE Name=?', (name, ))
        sid = self._update_source(rec[0]) \
            if rec is not None else \
            self._create_source(name, None, None)

        with self.conn.transaction() as tr:
            self._delete_source(sid)
            self._ingest(sid, rules)
            tr.commit()
        if sync:
            self.sync()

    def ingest_string(self, name: str, rules: str, sync: bool = True):
        """
        parse and ingest ruleset from string

        :param name:  name of source
        :param rules: rules to ingest
        :param sync:  sync database after ingestion
        """
        s    = StringIO(rules)
        rgen = parse_rules(s)
        self.ingest(name, rgen, sync)

    def ingest_file(self,
        fpath: str, name: Optional[str] = None, sync: bool = True) -> bool:
        """
        parse and ingest ruleset from the specified filepath

        :param fpath: filepath containing rules to add to rule engine
        :param name:  custom name of source for items in db
        :param sync:  sync database after ingestion
        :return:      if file was ingested or skipped
        """
        name = name or os.path.basename(fpath)
        time = datetime.fromtimestamp(os.path.getmtime(fpath))

        sql = 'SELECT SourceId,LastUpdated FROM Sources WHERE Path=?'
        rec = self.conn.fetch_one(sql, (fpath, ))
        if rec is not None and datetime.fromisoformat(rec[1]) == time:
            return False

        with self.conn.transaction() as tr:
            sid = self._update_source(rec[0]) \
                if rec is not None else \
                self._create_source(name, fpath, time)
            self._delete_source(sid)
            with open(fpath, 'r') as f:
                rules = parse_rules(f)
                self._ingest(sid, rules)
            tr.commit()

        if sync:
            self.sync()
        return True

    def count_blocked(self) -> int:
        """
        count the number of blocked rule entries
        """
        count = 0
        for stmt in (
            'SELECT COUNT(1) FROM RegexPatterns WHERE Rule=0',
            'SELECT COUNT(1) FROM WildcardPatterns WHERE Rule=0',
            'SELECT COUNT(1) FROM Domains WHERE Rule=0',
        ):
            rec    = self.conn.fetch_one(stmt)
            count += rec[0] if rec else 0
        return count

    def match_domain(self, domain: bytes) -> Optional[RStatus]:
        """
        match domain against dbm database of rules

        :param domain: domain to check if in database
        :return:       rule determination (if found)
        """
        sql = 'SELECT Rule FROM Domains WHERE Domain=? LIMIT 1'
        rec = self.conn.fetch_one(sql, (domain.decode('latin1'), ))
        if rec is not None:
            (status, ) = rec
            return RStatus.WHITELIST if status else RStatus.BLACKLIST
        return None

    def match_pattern(self, domain: bytes) -> Optional[RStatus]:
        """
        match domain against existing pattern based rules

        :param domain: domain to check if matching pattern rules
        :return:       rule determination (if matched)
        """
        if any(w.match(domain) for w in self.wildcard_allow):
            return RStatus.WHITELIST
        s_domain = domain.decode('latin1')
        if any(r.match(s_domain) for r in self.regex_allow):
            return RStatus.WHITELIST
        if any(w.match(domain) for w in self.wildcard_block):
            return RStatus.BLACKLIST
        if any(r.match(s_domain) for r in self.regex_block):
            return RStatus.BLACKLIST
        return None
