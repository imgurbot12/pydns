"""
Simple Sqlite3 Statistics Storage Implementation
"""
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from . import Stats, StatStorage, date_now
from .... import RType

#** Variables **#
__all__ = ['SqliteStatStore']

#: schema file location
SCHEMA = os.path.join(os.path.dirname(__file__), 'schema.sql')

def round_date(now: datetime) -> datetime:
    """
    round date to the nearest hour
    """
    return now.replace(minute=0, second=0, microsecond=0)

#** Classes **#

class SqliteStatStore(StatStorage):
    """
    Sqlite3 Statistics Storage Implementation
    """
    __slots__ = ('conn', )

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, autocommit=True)
        self.conn.execute('PRAGMA journal_mode=WAL')
        with open(SCHEMA, 'r') as f:
            self.conn.executescript(f.read())
        self.conn.autocommit = False

    def stats(self, span: timedelta = timedelta(hours=24)) -> List[Stats]:
        """
        retrieve stats grouped by hour for the specified time-span
        """
        now:   datetime = date_now() - span
        stats: Dict[datetime, Stats] = {}

        cur = self.conn.cursor()
        sql = 'SELECT * FROM Stats WHERE Date>=?'
        cur.execute(sql, (now.isoformat(), ))
        for row in cur.fetchall():
            (s_date, authority, blocked, questions) = row
            date = datetime.fromisoformat(s_date)
            if date not in stats:
                stats[date] = Stats(date=date)

            stat = stats[date]
            stat.total_queries   += questions
            stat.blocked_queries += blocked
            stat.with_authority  += authority

            sql = 'SELECT RType,Count FROM Questions WHERE Date=?'
            for (rtype, count) in cur.execute(sql, (s_date, )):
                rtype = RType[rtype]
                stat.query_counts.setdefault(rtype, 0)
                stat.query_counts[rtype] += count
            sql = 'SELECT Source,Count FROM Sources WHERE Date=?'
            for (source, count) in cur.execute(sql, (s_date, )):
                stat.query_sources.setdefault(source, 0)
                stat.query_sources[source] += count

        final = list(stats.values())
        final.sort(key=lambda s: s.date)
        return final

    def _upsert(self, cur: sqlite3.Cursor, now: Optional[datetime],
        field: str, count: int):
        """
        attempt to update global stats records but insert if data is missing
        """
        date = (now or date_now()).isoformat()
        sql  = f'UPDATE Stats SET {field}={field}+? WHERE Date=?'
        cur.execute(sql, (count, date))
        if cur.rowcount < 1:
            insert = 'INSERT INTO Stats VALUES (?, 0, 0, 0)'
            cur.execute(insert, (date, ))
            cur.execute(sql, (count, date))

    def _upsert2(self, cur: sqlite3.Cursor, now: Optional[datetime],
        table: str, field: str, value: str, count: int):
        """
        attempt to update secondary records but insert if data is missing
        """
        date = (now or date_now()).isoformat()
        sql  = f'UPDATE {table} SET Count=Count+? WHERE Date=? AND {field}=?'
        cur.execute(sql, (count, date, value))
        if cur.rowcount < 1:
            sql = f'INSERT INTO {table} VALUES (?, ?, ?)'
            cur.execute(sql, (date, value, count))

    def count_authority(self, count: int = 1, now: Optional[datetime] = None):
        cur = self.conn.cursor()
        now = round_date(now) if now else None
        self._upsert(cur, now, 'Authority', count)
        self.conn.commit()

    def count_question(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        cur = self.conn.cursor()
        now = round_date(now) if now else None
        self._upsert(cur, now, 'Questions', count)
        self._upsert2(cur, now, 'Questions', 'RType', rtype.name, count)
        self.conn.commit()

    def count_block(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        cur = self.conn.cursor()
        now = round_date(now) if now else None
        self._upsert(cur, now, 'Blocked', count)
        self._upsert2(cur, now, 'Blocked', 'RType', rtype.name, count)
        self.conn.commit()

    def count_source(self, source: str,
        count: int = 1, now: Optional[datetime] = None):
        cur = self.conn.cursor()
        now = round_date(now) if now else None
        self._upsert2(cur, now, 'Sources', 'Source', source, count)
        self.conn.commit()
