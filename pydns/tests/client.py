"""
DNS Client UnitTests
"""
from unittest import IsolatedAsyncioTestCase, skip

from .. import Question, RCode, RType
from ..client import BaseClient, HttpsClient, TcpClient, UdpClient

#** Variables **#
__all__ = ['ClientTests']

#** Classes **#

class ClientTests(IsolatedAsyncioTestCase):
    """
    DNS Message Packet Parsing/Construction UnitTests
    """
    client: BaseClient

    async def asyncTearDown(self) -> None:
        if hasattr(self, 'client'):
            pool = getattr(self.client, 'pool', None)
            if pool is not None:
                await pool.drain()

    async def test_udp_client(self):
        """
        Ensure UDP client works as intended
        """
        self.client = UdpClient([('1.1.1.1', 53)])
        response = await self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, '1.1.1.1')

    async def test_tcp_client(self):
        """
        Ensure TCP client works as intended
        """
        self.client = TcpClient([('1.1.1.1', 53)])
        response = await self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, '1.1.1.1')

    @skip('')
    async def test_https_client(self):
        """
        Ensure HTTPS client works as intended
        """
        self.client = HttpsClient()
        response = await self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, self.client.url)
