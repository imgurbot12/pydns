"""
DNS Server RuleSet Backend Engine UnitTests
"""
import tempfile
from io import StringIO
from ipaddress import IPv4Address
from typing import Optional
from unittest import IsolatedAsyncioTestCase

from .. import RCode, RType, Answer, A
from ..server.backend import *
from ..server.backend.ruleset.parser import *

#** Variables **#
__all__ = ['RuleSetTests']

RULE_LIST = """
||example.com^
||middle.*.foo.com^
||*.bar.com^
||baz.*^

@@||allowed.example.com^|
@@||middle.allowed.foo.com^|
@@/^[a-z]-allowed.bar.com$/
@@||baz.g*^|
"""

#** Classes **#

class RuleSetTests(IsolatedAsyncioTestCase):
    """
    DNS Server RuleSet Backend UnitTests
    """

    def setUp(self):
        self.engine = RuleEngineDB(':memory:')
        self.backend = RuleBackend(MemoryBackend(), engine=self.engine)

    def assertRule(self, rdef: RuleDef, rule: Rule, status: RStatus):
        """
        Assert the given rule definition matches the specified rule/status
        """
        self.assertEqual(rdef.rule, rule)
        self.assertIsInstance(rdef.rule, type(rule))
        self.assertEqual(rdef.status, status)

    async def assertDomain(self, domain: bytes, status: Optional[RStatus]):
        """
        Assert the given domain matches a record with the specified status
        """
        self.assertEqual(await self.engine.match_domain(domain), status)

    async def assertPattern(self, domain: bytes, status: Optional[RStatus]):
        """
        Assert the given domain matches a pattern with the specified status
        """
        self.assertEqual(await self.engine.match_pattern(domain), status)

    async def test_parser(self):
        """
        Ensure rule parsing works as intended
        """
        s     = StringIO(RULE_LIST)
        rules = list(parse_rules(s))
        self.assertEqual(len(rules), 8)
        for rule, expected in zip(rules, [
            (Domain('example.com'), RStatus.BLACKLIST),
            (Wildcard('middle.*.foo.com'), RStatus.BLACKLIST),
            (Wildcard('*.bar.com'), RStatus.BLACKLIST),
            (Wildcard('baz.*'), RStatus.BLACKLIST),
            (Domain('allowed.example.com'), RStatus.WHITELIST),
            (Domain('middle.allowed.foo.com'), RStatus.WHITELIST),
            (Regex('^[a-z]-allowed.bar.com$'), RStatus.WHITELIST),
            (Wildcard('baz.g*'), RStatus.WHITELIST)
        ]):
            self.assertRule(rule, *expected)

    async def test_engine_ingest(self):
        """
        ensure engine ingestion doesn't bork
        """
        with tempfile.NamedTemporaryFile() as f:
            f.write(RULE_LIST.encode())
            f.flush()
            f.seek(0, 0)
            self.assertTrue(self.engine.ingest_file(f.name, 'test'))
            self.assertFalse(self.engine.ingest_file(f.name, 'test'))
        await self.assertDomain(b'example.com', RStatus.BLACKLIST)
        await self.assertDomain(b'allowed.example.com', RStatus.WHITELIST)
        await self.assertDomain(b'middle.allowed.foo.com', RStatus.WHITELIST)
        await self.assertDomain(b'foo.example.com', None)
        await self.assertPattern(b'middle.one.foo.com', RStatus.BLACKLIST)
        await self.assertPattern(b'twooooooo.bar.com', RStatus.BLACKLIST)
        await self.assertPattern(b'A-allowed.bar.com', RStatus.BLACKLIST)
        await self.assertPattern(b'a-allowed.bar.com', RStatus.WHITELIST)
        await self.assertPattern(b'b-allowed.bar.com', RStatus.WHITELIST)
        await self.assertPattern(b'baz.io', RStatus.BLACKLIST)
        await self.assertPattern(b'baz.gov', RStatus.WHITELIST)

    async def test_backend_answer(self):
        """
        Ensure backend produces the correct answers
        """
        self.engine.ingest_string('test', RULE_LIST)
        answers = await self.backend.get_answers(b'allowed.example.com', RType.A)
        self.assertListEqual([], answers.answers)
        self.assertEqual('MemDB', answers.source)

        answers = await self.backend.get_answers(b'youtube.com', RType.A)
        self.assertListEqual([], answers.answers)
        self.assertEqual('MemDB', answers.source)

        domain = b'example.com'
        answers = await self.backend.get_answers(domain, RType.A)
        self.assertListEqual([], answers.answers)
        self.assertEqual(self.backend.source, answers.source)
        self.assertIsNone(answers.rcode)

        self.backend.block_mode = BlockMode.NULL
        answers = await self.backend.get_answers(domain, RType.A)
        expect  = Answer(domain, 60, A(IPv4Address('0.0.0.0')))
        self.assertListEqual([expect], answers.answers)
        self.assertEqual(self.backend.source, answers.source)
        self.assertIsNone(answers.rcode)

        self.backend.block_mode = BlockMode.NXDOMAIN
        answers = await self.backend.get_answers(domain, RType.A)
        self.assertListEqual([], answers.answers)
        self.assertEqual(self.backend.source, answers.source)
        self.assertEqual(RCode.NonExistantDomain, answers.rcode)
