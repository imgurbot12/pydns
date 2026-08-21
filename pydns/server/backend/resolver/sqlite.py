"""
Simple Sqlite3 Resolver Cache Implementation
"""
import os
import sqlite3
from datetime import datetime
from typing import Any, List, Optional, Type
from typing_extensions import Annotated, get_origin, get_args

from pyderive.extensions.serde import (
    TypeEncoder, TypeDecoder, serialize, deserialize)

from . import Record, ResolverCache
from .... import RType
from ....content import CONTENT_MAP

#** Variables **#
__all__ = ['SqliteResolverCache']

#: schema file location
SCHEMA = os.path.join(os.path.dirname(__file__), '../_sql/resolver.sql')

#** Classes **#

class Encoder(TypeEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)

class Decoder(TypeDecoder):
    def default(self, anno: Type, obj: Any) -> Any:
        if anno is bytes \
            or (get_origin(anno) is Annotated and get_args(anno)[0] is bytes):
            return bytes.fromhex(obj)
        return super().default(anno, obj)

class SqliteResolverCache(ResolverCache):
    """
    """
    __slots__ = ('conn', )

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, autocommit=True)
        self.conn.execute('PRAGMA journal_mode=WAL')
        with open(SCHEMA, 'r') as f:
            self.conn.executescript(f.read())
        self.conn.autocommit = True

    def _domain_id(self, cur: sqlite3.Cursor, domain: bytes) -> int:
        """
        """
        dom = domain.decode('latin1')
        sql = 'SELECT DomainId FROM Domains WHERE Domain=?'
        cur.execute(sql, (dom, ))
        rec = cur.fetchone()
        if rec is not None:
            return rec[0]
        cur.execute('SELECT MAX(DomainId)+1 FROM Domains')
        (did, ) = cur.fetchone()
        did     = did or 1
        cur.execute('INSERT INTO Domains VALUES (?, ?)', (did, dom))
        return did

    def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        cclass = CONTENT_MAP[rtype]
        now = datetime.now()
        cur = self.conn.cursor()
        did = self._domain_id(cur, domain)
        sql = 'SELECT Content,Expiration FROM Records WHERE DomainId=? AND RType=?'
        cur.execute(sql, (did, rtype.name))
        records = []
        expired = 0
        for row in cur.fetchall():
            (content, expiration) = row
            content    = deserialize(cclass, content, 'json', decoder=Decoder())
            expiration = datetime.fromisoformat(expiration)
            if expiration <= now:
                expired += 1
                continue
            records.append(Record(content, expiration))
        if expired:
            sql = 'DELETE FROM Records WHERE Expiration<=?'
            cur.execute(sql, (now.isoformat(), ))
        return records if records else None

    def put(self, domain: bytes, rtype: RType, records: List[Record]):
        cur    = self.conn.cursor()
        did    = self._domain_id(cur, domain)
        values = []
        args   = []
        for record in records:
            values.append('(?, ?, ?, ?)')
            content    = serialize(record.content, 'json', encoder=Encoder())
            expiration = record.expiration.isoformat()
            args.extend([did, rtype.name, content, expiration])
        sql = 'INSERT INTO Records VALUES ' + ','.join(values)
        cur.execute(sql, tuple(args))
