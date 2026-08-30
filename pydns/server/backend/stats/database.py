"""
Simple Database Statistics Storage Implementation
"""
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from . import Stats, StatStorage, date_now
from .._sql import stats_db
from .... import RType

#** Variables **#
__all__ = ['StatStoreDB']

#: schema file location
SCHEMA = os.path.join(os.path.dirname(__file__), '../_sql/stats.sql')

def round_date(now: datetime) -> datetime:
    """
    round date to the nearest hour
    """
    return now.replace(minute=0, second=0, microsecond=0)

#** Classes **#

class StatStoreDB(StatStorage):
    """
    Sqlite3 Statistics Storage Implementation
    """
    __slots__ = ('conn', )

    def __init__(self, path: str):
        self.conn = stats_db(path)

    def stats(self, span: timedelta = timedelta(hours=24)) -> List[Stats]:
        """
        retrieve stats grouped by hour for the specified time-span
        """
        now:   datetime = date_now()
        then:  datetime = now - span
        stats: Dict[datetime, Stats] = {}

        sql = 'SELECT * FROM Stats WHERE Date>=?'
        for row in self.conn.fetch_all(sql, (then.isoformat(), )):
            (s_date, authority, blocked, questions) = row
            date = datetime.fromisoformat(s_date)
            if date not in stats:
                stats[date] = Stats(date=date)

            stat = stats[date]
            stat.total_queries   += questions
            stat.blocked_queries += blocked
            stat.with_authority  += authority

            sql = 'SELECT RType,Count FROM Questions WHERE Date=?'
            for (rtype, count) in self.conn.fetch_all(sql, (s_date, )):
                rtype = RType[rtype]
                stat.query_counts.setdefault(rtype, 0)
                stat.query_counts[rtype] += count
            sql = 'SELECT Source,Count FROM Sources WHERE Date=?'
            for (source, count) in self.conn.fetch_all(sql, (s_date, )):
                stat.query_sources.setdefault(source, 0)
                stat.query_sources[source] += count

        total_hours = int(span.total_seconds() // 3600)
        for hour in range(0, total_hours):
            then = now - timedelta(hours=hour)
            if then not in stats:
                stats[then] = Stats(date=then)

        final = list(stats.values())
        final.sort(key=lambda s: s.date)
        return final

    def _upsert(self, now: Optional[datetime],
        field: str, count: int):
        """
        attempt to update global stats records but insert if data is missing
        """
        date  = (now or date_now()).isoformat()
        sql   = f'UPDATE Stats SET {field}={field}+? WHERE Date=?'
        if self.conn.execute(sql, (count, date)) < 1:
            insert = 'INSERT INTO Stats VALUES (?, 0, 0, 0)'
            self.conn.execute(insert, (date, ))
            self.conn.execute(sql, (count, date))

    def _upsert2(self, now: Optional[datetime],
        table: str, field: str, value: str, count: int):
        """
        attempt to update secondary records but insert if data is missing
        """
        date = (now or date_now()).isoformat()
        sql  = f'UPDATE {table} SET Count=Count+? WHERE Date=? AND {field}=?'
        if self.conn.execute(sql, (count, date, value)) < 1:
            sql = f'INSERT INTO {table} VALUES (?, ?, ?)'
            self.conn.execute(sql, (date, value, count))

    def count_authority(self, count: int = 1, now: Optional[datetime] = None):
        now = round_date(now) if now else None
        self._upsert(now, 'Authority', count)

    def count_question(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        now = round_date(now) if now else None
        self._upsert(now, 'Questions', count)
        self._upsert2(now, 'Questions', 'RType', rtype.name, count)

    def count_block(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        now = round_date(now) if now else None
        self._upsert(now, 'Blocked', count)
        self._upsert2(now, 'Blocked', 'RType', rtype.name, count)

    def count_source(self, source: str,
        count: int = 1, now: Optional[datetime] = None):
        now = round_date(now) if now else None
        self._upsert2(now, 'Sources', 'Source', source, count)
