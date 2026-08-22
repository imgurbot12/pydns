"""
DNS Recursive Resolver Backend Engine UnitTests
"""
from typing import List, Optional, Type
from unittest import TestCase

from .. import A, NS, RType, Answer
from ..content import Content
from ..server.backend.resolver import MemoryCache, Record, Resolver

#** Variables **#
__all__ = ['ResolverTests']

#** Classes **#


class ResolverTests(TestCase):
    """
    DNS Recurisve Resolver Backend UnitTests
    """

    def setUp(self) -> None:
        self.cache    = MemoryCache()
        self.resolver = Resolver(cache=self.cache)

    def assertAnswers(self,
        answers: Optional[List[Answer]], rclass: Type[Content]):
        """
        assert answers are not empty and match the given class
        """
        self.assertIsNotNone(answers)
        answers = answers or []
        self.assertGreater(len(answers), 0)
        self.assertTrue(all(isinstance(a.content, rclass) for a in answers))

    def assertRecords(self,
        records: Optional[List[Record]], rclass: Type[Content]):
        """
        assert records are not empty and match the given class
        """
        self.assertIsNotNone(records)
        records = records or []
        self.assertGreater(len(records), 0)
        self.assertTrue(all(isinstance(r.content, rclass) for r in records))

    def test_cache(self):
        """
        ensure cache/lookups are working as intended
        """
        answers = self.resolver.resolve(b'www.google.com', RType.A)
        self.assertAnswers(answers, A)

        com            = self.cache.get(b'com', RType.NS)
        google_com     = self.cache.get(b'google.com', RType.NS)
        www_google_com = self.cache.get(b'www.google.com', RType.A)
        self.assertRecords(com, NS)
        self.assertRecords(google_com, NS)
        self.assertRecords(www_google_com, A)

