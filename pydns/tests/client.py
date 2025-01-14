"""
DNS Client UnitTests
"""
from unittest import TestCase

from .. import Question, RCode, RType
from ..client import HttpsClient, TcpClient, UdpClient

#** Variables **#
__all__ = ['ClientTests']

#** Classes **#

class ClientTests(TestCase):
    """
    DNS Message Packet Parsing/Construction UnitTests
    """

    def test_udp_client(self):
        """
        ensure udp client works as intended
        """
        client   = UdpClient([('1.1.1.1', 53)])
        response = client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})

    def test_tcp_client(self):
        """
        ensure tcp client works as intended
        """
        client   = TcpClient([('1.1.1.1', 53)])
        response = client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})

    def test_https_client(self):
        """
        ensure https client works as intended
        """
        client   = HttpsClient()
        response = client.query(Question(b'one.one.one.one', RType.A))
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.answers), 2)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(response.answers[1].rtype, RType.A)
        self.assertEqual({str(a.content.ip) for a in response.answers}, #type: ignore
            {'1.0.0.1', '1.1.1.1'})
