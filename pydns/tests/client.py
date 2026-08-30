"""
DNS Client UnitTests
"""
from unittest import TestCase, skip

from .. import Question, RCode, RType
from ..client import BaseClient, HttpsClient, TcpClient, UdpClient

#** Variables **#
__all__ = ['ClientTests']

#** Classes **#

class ClientTests(TestCase):
    """
    DNS Message Packet Parsing/Construction UnitTests
    """
    client: BaseClient

    def tearDown(self) -> None:
        if hasattr(self, 'client'):
            pool = getattr(self.client, 'pool', None)
            if pool is not None:
                pool.drain()

    def test_udp_client(self):
        """
        ensure udp client works as intended
        """
        self.client = UdpClient([('1.1.1.1', 53)])
        response = self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, '1.1.1.1')

    def test_tcp_client(self):
        """
        ensure tcp client works as intended
        """
        self.client = TcpClient([('1.1.1.1', 53)])
        response = self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, '1.1.1.1')

    @skip('')
    def test_https_client(self):
        """
        ensure https client works as intended
        """
        self.client = HttpsClient()
        response = self.client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
        self.assertEqual(response.source, self.client.url)
