"""
Thread-Safe Wrapper for SQLite Backends
"""
import os
from typing import Any

from anysql import Database

#** Variables **#
__all__ = ['resolver_db', 'ruleset_db', 'stats_db']

DIR          = os.path.dirname(__file__)
RESOLVER_SQL = os.path.join(DIR, 'resolver.sql')
RULESET_SQL  = os.path.join(DIR, 'ruleset.sql')
STATS_SQL    = os.path.join(DIR, 'stats.sql')

#** Functions **#

def _connect(path: str, sqlfile: str, **kwargs: Any) -> Database:
    uri      = path if '://' in path else f'sqlite://{path}'
    database = Database(uri, **kwargs)
    database.connect()

    if 'sqlite' in database.uri.scheme:
        database.execute('PRAGMA journal_mode=WAL')

    with open(sqlfile, 'r') as f:
        sql = f.read()
        statements = [s.strip() for s in sql.split(';')]
        statements = [s for s in statements if s]

    with database.transaction() as tr:
        for sql in statements:
            database.execute(sql)
        tr.commit()
    return database

def resolver_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return _connect(path, RESOLVER_SQL, **kwargs)

def ruleset_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return _connect(path, RULESET_SQL, **kwargs)

def stats_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return _connect(path, STATS_SQL, **kwargs)
