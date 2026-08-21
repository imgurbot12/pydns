"""
DNS Client Implementation
"""
from abc import abstractmethod
from random import randint
from typing import Protocol

from ..enum import QR, OpCode
from ..flags import Flags
from ..question import Question
from ..message import Message

#** Variables **#
__all__ = ['BaseClient', 'UdpClient', 'TcpClient', 'HttpsClient']

#** Functions **#

def new_message_id() -> int:
    """
    generate a new valid id for a dns message packet

    :return: new valid message-id integer
    """
    return randint(1, 2 ** 16)

#** Classes **#

class BaseClient(Protocol):

    @abstractmethod
    def request(self, msg: Message) -> Message:
        """
        send request and proces recieved response

        :param msg: dns request  message
        :return:    dns response message
        """
        raise NotImplementedError

    def _build_query(self, query: Question) -> Message:
        """
        build query request message from question
        """
        mid     = new_message_id()
        flags   = Flags(qr=QR.Question, op=OpCode.Query)
        return Message(id=mid, flags=flags, questions=[query])

    def query(self, query: Question) -> Message:
        """
        build request message from query and return response

        :param query: simple dns query
        :return:      response message to query
        """
        message = self._build_query(query)
        return self.request(message)

#** Imports **#
from .https import HttpsClient
from .standard import UdpClient, TcpClient
