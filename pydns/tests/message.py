"""
DNS Message Packing/Unpacking UnitTests
"""
from unittest import TestCase

from .. import Message, OpCode, QR, RClass, RCode, RType
from ..edns import EdnsAnswer

#** Variables **#
__all__ = ['MessageTests']

EXAMPLE_REQUEST = 'a32701200001000000000001076578616d706c6503' +\
    '636f6d000001000100002904d000000000000c000a0008c5a01ecf50bd546c'

EXAMPLE_RESPONSE = 'a32781a00001000100000001076578616d706c650' +\
    '3636f6d0000010001c00c000100010000001e00045db8d70e0000290200000000000000'

#** Classes **#

class MessageTests(TestCase):
    """
    DNS Message Packet Parsing/Construction UnitTests
    """

    def test_parse_request(self):
        """
        ensure request parsing works as intended
        """
        data    = bytes.fromhex(EXAMPLE_REQUEST)
        request = Message.unpack(data)
        self.assertEqual(request.id, 0xa327)
        self.assertEqual(request.flags.qr, QR.Question)
        self.assertEqual(request.flags.op, OpCode.Query)
        self.assertEqual(request.flags.authorative, False)
        self.assertEqual(request.flags.truncated, False)
        self.assertEqual(request.flags.recursion_desired, True)
        self.assertEqual(request.flags.recursion_available, False)
        self.assertEqual(request.flags.answer_authenticated, True)
        self.assertEqual(request.flags.checking_disabled, False)
        self.assertEqual(request.flags.rcode, RCode.NoError)
        self.assertEqual(len(request.questions), 1)
        self.assertEqual(len(request.answers), 0)
        self.assertEqual(len(request.authority), 0)
        self.assertEqual(len(request.additional), 1)
        self.assertEqual(request.questions[0].name, b'example.com')
        self.assertEqual(request.questions[0].qtype, RType.A)
        self.assertEqual(request.questions[0].qclass, RClass.IN)
        self.assertIsInstance(request.additional[0], EdnsAnswer)
        self.assertEqual(request.additional[0].name, b'')

    def test_pack_request(self):
        """
        ensure request packing works as intended
        """
        data    = bytes.fromhex(EXAMPLE_REQUEST)
        request = Message.unpack(data)
        data_2  = request.pack()
        self.assertEqual(data, data_2)

    def test_parse_response(self):
        """
        ensure response parsing works as intended
        """
        data     = bytes.fromhex(EXAMPLE_RESPONSE)
        response = Message.unpack(data)
        self.assertEqual(response.id, 0xa327)
        self.assertEqual(response.flags.qr, QR.Response)
        self.assertEqual(response.flags.op, OpCode.Query)
        self.assertEqual(response.flags.authorative, False)
        self.assertEqual(response.flags.truncated, False)
        self.assertEqual(response.flags.recursion_desired, True)
        self.assertEqual(response.flags.recursion_available, True)
        self.assertEqual(response.flags.answer_authenticated, True)
        self.assertEqual(response.flags.checking_disabled, False)
        self.assertEqual(response.flags.rcode, RCode.NoError)
        self.assertEqual(len(response.questions), 1)
        self.assertEqual(len(response.answers), 1)
        self.assertEqual(len(response.authority), 0)
        self.assertEqual(len(response.additional), 1)
        self.assertEqual(response.questions[0].name, b'example.com')
        self.assertEqual(response.questions[0].qtype, RType.A)
        self.assertEqual(response.questions[0].qclass, RClass.IN)
        self.assertEqual(response.answers[0].name, b'example.com')
        self.assertEqual(response.answers[0].ttl, 30)
        self.assertEqual(response.answers[0].rtype, RType.A)
        self.assertEqual(str(response.answers[0].content.ip), '93.184.215.14') #type: ignore
        self.assertEqual(response.answers[0].rclass, RClass.IN)
        self.assertIsInstance(response.additional[0], EdnsAnswer)
        self.assertEqual(response.additional[0].name, b'')

    def test_pack_response(self):
        """
        ensure response packing works as intended
        """
        data     = bytes.fromhex(EXAMPLE_REQUEST)
        response = Message.unpack(data)
        data_2   = response.pack()
        self.assertEqual(data, data_2)
