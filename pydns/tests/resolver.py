"""
DNS Recursive Resolver Backend Engine UnitTests
"""
from typing import List, Optional, Type
from unittest import IsolatedAsyncioTestCase

from .. import A, NS, RType, Answer
from ..content import Unknown
from ..server.backend.resolver import Record, Resolver, ResolverCacheDB

#** Variables **#
__all__ = ['ResolverTests']

#** Classes **#

class ResolverTests(IsolatedAsyncioTestCase):
    """
    DNS Recursive Resolver Backend UnitTests
    """

    def setUp(self) -> None:
        self.cache    = ResolverCacheDB('sqlite://:memory:')
        self.resolver = Resolver(cache=self.cache)

    async def asyncTearDown(self) -> None:
        await self.resolver.client.pool.drain()
        if self.cache._conn is not None:
            await self.cache._conn.disconnect()

    def assertAnswers(self,
        answers: Optional[List[Answer]], rclass: Type):
        """
        Assert answers are not empty and match the given class
        """
        self.assertIsNotNone(answers)
        answers = answers or []
        self.assertGreater(len(answers), 0)
        self.assertTrue(all(isinstance(a.content, rclass) for a in answers))

    def assertRecords(self,
        records: Optional[List[Record]], rclass: Type):
        """
        Assert records are not empty and match the given class
        """
        self.assertIsNotNone(records)
        records = records or []
        self.assertGreater(len(records), 0)
        self.assertTrue(all(isinstance(r.content, rclass) for r in records))

    async def test_cache(self):
        """
        Ensure cache/lookups are working as intended
        """
        answers = await self.resolver.resolve(b'www.google.com', RType.A)
        self.assertAnswers(answers, A)

        com            = await self.cache.get(b'com', RType.NS)
        google_com     = await self.cache.get(b'google.com', RType.NS)
        www_google_com = await self.cache.get(b'www.google.com', RType.A)
        self.assertRecords(com, NS)
        self.assertRecords(google_com, NS)
        self.assertRecords(www_google_com, A)

    async def test_unknown(self):
        """
        """
        answers = await self.resolver.resolve(b'www.google.com', RType.HTTPS)
        self.assertAnswers(answers, Unknown)
        answers = answers or []
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0].content.rtype, RType.HTTPS)

        https = await self.cache.get(b'www.google.com', RType.HTTPS) or []
        self.assertRecords(https, Unknown)
        self.assertEqual(len(https), 1)
        self.assertEqual(answers[0].content.rtype, RType.HTTPS)

