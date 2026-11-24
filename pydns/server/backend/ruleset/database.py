"""
Simple Sqlite3 Database Implementation for Rule Engine
"""
import os
import re
from io import StringIO
from datetime import datetime
from typing import List, Optional

from . import RuleEngine, RStatus
from .parser import RuleDefs, Domain, Regex, Wildcard, parse_rules
from .wildcard import WildcardMatch
from .._sql import Connection, Database, ruleset_db

#** Variables **#
__all__ = ['RuleEngineDB']

#** Classes **#

class RuleEngineDB(RuleEngine):
    """
    Simple SQLite Supported Rule Engine for RuleBackend
    """
    __slots__ = ('_conn', '_path', '_sync',
        'regex_allow', 'regex_block' 'wildcard_allow', 'wildcard_block')

    regex_allow:    List[re.Pattern]
    regex_block:    List[re.Pattern]
    wildcard_allow: List[WildcardMatch]
    wildcard_block: List[WildcardMatch]

    def __init__(self, path: str, sync: bool = True):
        self._conn = None
        self._path = path
        self._sync = sync

    async def conn(self) -> Database:
        """
        Retrieve SQLite Database Connection
        """
        if self._conn is None:
            self._conn = await ruleset_db(self._path)
            if self._sync:
                await self.sync()
        return self._conn

    def _create_source(self, conn: Connection, name: str,
        path: Optional[str], date: Optional[datetime]) -> int:
        """
        Create a new source record with a unique id
        """
        date = date or datetime.now()
        rec  = conn.fetch_one('SELECT MAX(SourceId)+1 FROM Sources')
        sid  = (rec[0] if rec else 1) or 1
        sql  = 'INSERT INTO Sources VALUES (?, ?, ?, ?)'
        conn.execute(sql, (sid, name, path, date.isoformat()))
        return sid

    def _update_source(self, conn: Connection, sid: int) -> int:
        """
        Update the last-updated datetime tracker for the specific source
        """
        sql  = "UPDATE Sources SET LastUpdated=datetime('now') WHERE SourceId=?"
        conn.execute(sql, (sid, ))
        return sid

    def _delete_source(self, conn: Connection, sid: int):
        """
        Delete all patterns and domains associated with a specific source
        """
        args = (sid, )
        for stmt in (
            'DELETE FROM RegexPatterns WHERE SourceId=?',
            'DELETE FROM WildcardPatterns WHERE SourceId=?',
            'DELETE FROM Domains WHERE SourceId=?',
        ):
            conn.execute(stmt, args)

    def _ingest(self, conn: Connection, sid: int, rules: RuleDefs):
        """
        Add all the given rules to the specified source
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
        conn.execute_many(
            'INSERT INTO RegexPatterns VALUES (?, ?, ?)', regex)
        conn.execute_many(
            'INSERT INTO WildcardPatterns VALUES (?, ?, ?)', wildcards)
        conn.execute_many(
            'INSERT INTO Domains VALUES (?, ?, ?)', domains)

    async def sync(self):
        """
        Compile regex and wildcard expressions within database
        """
        conn         = await self.conn()
        sql_regex    = 'SELECT Pattern,Rule FROM RegexPatterns'
        sql_wildcard = 'SELECT Pattern,Rule FROM WildcardPatterns'
        self.regex_allow    = []
        self.regex_block    = []
        self.wildcard_allow = []
        self.wildcard_block = []
        for row in await conn.fetch_all(sql_regex):
            (pattern, status) = row
            store = self.regex_allow \
                if status == RStatus.WHITELIST else self.regex_block
            store.append(re.compile(pattern))
        for row in await conn.fetch_all(sql_wildcard):
            (pattern, status) = row
            store = self.wildcard_allow \
                if status == RStatus.WHITELIST else self.wildcard_block
            store.append(WildcardMatch.compile(pattern))

    async def ingest(self, name: str, rules: RuleDefs, sync: bool = True):
        """
        Ingest incoming source of rule definitions and update database

        :param name:  name of source
        :param rules: rules to ingest
        :param sync:  sync database after ingestion
        """
        conn = await self.conn()
        rec  = await conn.fetch_one(
            'SELECT SourceId FROM Sources WHERE Name=?', (name, ))
        def tx(conn, tx):
            sid = self._update_source(conn, rec[0]) \
                if rec is not None else \
                self._create_source(conn, name, None, None)
            self._delete_source(conn, sid)
            self._ingest(conn, sid, rules)
            tx.commit()
        await conn.transaction(tx)
        if sync:
            await self.sync()

    async def ingest_string(self, name: str, rules: str, sync: bool = True):
        """
        Parse and ingest rule-set from string

        :param name:  name of source
        :param rules: rules to ingest
        :param sync:  sync database after ingestion
        """
        s    = StringIO(rules)
        rgen = parse_rules(s)
        await self.ingest(name, rgen, sync)

    async def ingest_file(self,
        fpath: str, name: Optional[str] = None, sync: bool = True) -> bool:
        """
        Parse and ingest rule-set from the specified filepath

        :param fpath: filepath containing rules to add to rule engine
        :param name:  custom name of source for items in db
        :param sync:  sync database after ingestion
        :return:      if file was ingested or skipped
        """
        name = name or os.path.basename(fpath)
        time = datetime.fromtimestamp(os.path.getmtime(fpath))
        conn = await self.conn()

        sql = 'SELECT SourceId,LastUpdated FROM Sources WHERE Path=?'
        rec = await conn.fetch_one(sql, (fpath, ))
        if rec is not None and datetime.fromisoformat(rec[1]) == time:
            return False

        def tx(conn, tx):
            sid = self._update_source(conn, rec[0]) \
                if rec is not None else \
                self._create_source(conn, name, fpath, time)
            self._delete_source(conn, sid)
            with open(fpath, 'r') as f:
                rules = parse_rules(f)
                self._ingest(conn, sid, rules)
            tx.commit()

        await conn.transaction(tx)
        if sync:
            await self.sync()
        return True

    async def count_blocked(self) -> int:
        """
        Count the number of blocked rule entries
        """
        count = 0
        conn  = await self.conn()
        for stmt in (
            'SELECT COUNT(1) FROM RegexPatterns WHERE Rule=0',
            'SELECT COUNT(1) FROM WildcardPatterns WHERE Rule=0',
            'SELECT COUNT(1) FROM Domains WHERE Rule=0',
        ):
            rec    = await conn.fetch_one(stmt)
            count += rec[0] if rec else 0
        return count

    async def match_domain(self, domain: bytes) -> Optional[RStatus]:
        """
        Match domain against database of rules
        """
        conn = await self.conn()
        sql  = 'SELECT Rule FROM Domains WHERE Domain=? LIMIT 1'
        rec  = await conn.fetch_one(sql, (domain.decode('latin1'), ))
        if rec is not None:
            (status, ) = rec
            return RStatus.WHITELIST if status else RStatus.BLACKLIST
        return None

    async def match_pattern(self, domain: bytes) -> Optional[RStatus]:
        """
        Match domain against existing pattern based rules
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
