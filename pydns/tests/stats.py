"""
DNS Server Stats Backend Engine UnitTests
"""
import random
from datetime import datetime, timedelta
from typing import List
from unittest import TestCase

from pydns.server.backend.stats import date_now

from .. import RType
from ..server.backend import *
from ..server.backend.stats.sqlite import round_date

#** Variables **#
__all__ = ['StatTests']

RTYPES  = [r for r in RType]
SOURCES = ['1.1.1.1', '8.8.8.8', 'local']

#** Classes **#

class StatTests(TestCase):
    """
    DNS Server Stats Backend UnitTests
    """

    def setUp(self):
        self.store   = SqliteStatStore(':memory:')
        self.backend = StatBackend(MemoryBackend(), self.store)

    def simulate(self, hours: int = 24) -> List[Stats]:
        """
        simulate query activity, record to stats, and return actual numbers
        """
        stats = []
        for hour in range(0, hours):
            now       = round_date(datetime.now() - timedelta(hours=hour))
            if random.randint(0, 3) == 1:
                stats.append(Stats(date=now))
                continue

            questions = random.randint(1, 10_000)
            blocked   = random.randint(1, questions)
            authority = random.randint(1, questions - blocked)

            rtypes  = {}
            sources = {}
            for rtype in random.choices(RTYPES, k=questions):
                rtypes.setdefault(rtype, 0)
                rtypes[rtype] += 1
            for source in random.choices(SOURCES, k=questions):
                sources.setdefault(source, 0)
                sources[source] += 1

            self.store.count_authority(authority, now)
            self.store.count_block(RType.A, blocked, now)
            for rtype, count in rtypes.items():
                self.store.count_question(rtype, count, now)
            for source, count in sources.items():
                self.store.count_source(source, count, now)
            stats.append(Stats(
                date=now,
                total_queries=questions,
                blocked_queries=blocked,
                with_authority=authority,
                query_counts=rtypes,
                query_sources=sources,
            ))
        stats.sort(key=lambda s: s.date)
        return stats

    def test_empty_stats(self):
        """
        ensure stat reporting still returns when empty
        """
        now   = date_now()
        stats = self.store.stats()
        self.assertEqual(len(stats), 24)
        for n, stat in enumerate(stats, 1):
            hour = now - timedelta(hours=24-n)
            self.assertEqual(stat.date, hour)
            self.assertEqual(stat.total_queries, 0)
            self.assertEqual(stat.blocked_queries, 0)
            self.assertEqual(stat.with_authority, 0)
            self.assertDictEqual(stat.query_counts, {})
            self.assertDictEqual(stat.query_sources, {})

    def test_full_stats(self):
        """
        ensure stat recording is accurate
        """
        expect = self.simulate()
        actual = self.store.stats()
        self.assertEqual(len(expect), len(actual))
        for s1, s2 in zip(expect, actual):
            self.assertEqual(s1.date, s2.date)
            self.assertEqual(s1.total_queries, s2.total_queries)
            self.assertEqual(s1.blocked_queries, s2.blocked_queries)
            self.assertEqual(s1.with_authority, s2.with_authority)
            self.assertDictEqual(s1.query_counts, s2.query_counts)
            self.assertDictEqual(s1.query_sources, s2.query_sources)


