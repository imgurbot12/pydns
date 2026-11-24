"""
Thread-Safe Wrapper for SQLite Backends
"""
import os
from typing import Any

from anysql.core import Connection
from anysql import AsyncDatabase as Database

#** Variables **#
__all__ = ['Connection', 'Database', 'resolver_db', 'ruleset_db', 'stats_db']

DIR          = os.path.dirname(__file__)
RESOLVER_SQL = os.path.join(DIR, 'resolver.sql')
RULESET_SQL  = os.path.join(DIR, 'ruleset.sql')
STATS_SQL    = os.path.join(DIR, 'stats.sql')

#** Functions **#

async def _connect(path: str, sqlfile: str, **kwargs: Any) -> Database:
    uri      = path if '://' in path else f'sqlite://{path}'
    database = Database(uri, **kwargs, autocommit=True)
    await database.connect()

    if 'sqlite' in database.uri.scheme:
        await database.execute('PRAGMA journal_mode=WAL')

    with open(sqlfile, 'r') as f:
        sql = f.read()
        statements = [s.strip() for s in sql.split(';')]
        statements = [s for s in statements if s]

    def tx(conn, tx):
        for sql in statements:
            conn.execute(sql)
        tx.commit()
    await database.transaction(tx)

    return database

async def resolver_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return await _connect(path, RESOLVER_SQL, **kwargs)

async def ruleset_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return await _connect(path, RULESET_SQL, **kwargs)

async def stats_db(path: str, **kwargs: Any) -> Database:
    """
    """
    return await _connect(path, STATS_SQL, **kwargs)
