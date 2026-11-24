"""
Simple Database Resolver Cache Implementation
"""
import json
from datetime import datetime
from typing import Any, List, Optional, Type, Union
from typing_extensions import Annotated, get_origin, get_args

from pyderive.extensions.serde import (
    TypeEncoder, TypeDecoder, serialize, deserialize)

from . import Record, ResolverCache
from .._sql import Database, resolver_db
from .... import RType
from ....content import CONTENT_MAP, Content, Unknown

#** Variables **#
__all__ = ['ResolverCacheDB']

#** Function **#

def ser_content(record: Record) -> Union[str, bytes]:
    """
    Serialize DNS content record (including unknown variants)
    """
    if isinstance(record.content, Unknown):
        unk   = record.content
        value = unk.data.decode('latin1')
        data  = {'rtype': unk.rtype.name, 'size': unk.size, 'data': value}
        return json.dumps(data)
    return serialize(record.content, 'json', encoder=Encoder())

def des_content(cclass: Optional[Type[Content]], serial: str) -> Content:
    """
    Deserialize DNS content record (including unknown variants)
    """
    if cclass is None:
        data    = json.loads(serial)
        rtype   = RType[data['rtype']]
        unk_cls = Unknown.new(rtype, data['size'])
        return unk_cls(data['data'].encode('latin1'))
    return deserialize(cclass, serial, 'json', decoder=Decoder())

#** Classes **#

class Encoder(TypeEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return obj.decode('latin1')
        return super().default(obj)

class Decoder(TypeDecoder):
    def default(self, anno: Type, obj: Any) -> Any:
        if anno is bytes \
            or (get_origin(anno) is Annotated and get_args(anno)[0] is bytes):
            return obj.encode('latin1')
        return super().default(anno, obj)

class ResolverCacheDB(ResolverCache):
    """
    """
    __slots__ = ('conn', )

    def __init__(self, path: str):
        self.conn = resolver_db(path).to_async()

    async def _domain_id(self, domain: bytes) -> int:
        """
        """
        dom  = domain.decode('latin1')
        sql  = 'SELECT DomainId FROM Domains WHERE Domain=?'
        rec  = await self.conn.fetch_one(sql, (domain, ))
        if rec is not None:
            return rec[0]
        rec = await self.conn.fetch_one('SELECT MAX(DomainId)+1 FROM Domains')
        did = (rec[0] if rec else 1) or 1
        await self.conn.execute('INSERT INTO Domains VALUES (?, ?)', (did, dom))
        return did

    async def get(self, domain: bytes, rtype: RType) -> Optional[List[Record]]:
        cclass = CONTENT_MAP.get(rtype, None)
        now  = datetime.now()
        did  = await self._domain_id(domain)
        sql  = 'SELECT Content,Expiration FROM Records WHERE DomainId=? AND RType=?'
        records = []
        expired = 0
        for row in await self.conn.fetch_all(sql, (did, rtype.name)):
            (content, expiration) = row
            content    = des_content(cclass, content)
            expiration = datetime.fromisoformat(expiration)
            if expiration <= now:
                expired += 1
                continue
            records.append(Record(content, expiration))
        if expired:
            sql = 'DELETE FROM Records WHERE Expiration<=?'
            await self.conn.execute(sql, (now.isoformat(), ))
        return records if records else None

    async def put(self, domain: bytes, rtype: RType, records: List[Record]):
        did    = await self._domain_id(domain)
        values = []
        args   = []
        for record in records:
            values.append(f'(?, ?, ?, ?)')
            content    = ser_content(record)
            expiration = record.expiration.isoformat()
            args.extend([did, rtype.name, content, expiration])
        sql = 'INSERT INTO Records VALUES ' + ','.join(values)
        await self.conn.execute(sql, args)
