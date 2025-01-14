"""
Standard UDP/TCP Client Implementations
"""
import random
import socket
from abc import ABC, abstractmethod
from typing import List, Optional

from pypool import Pool
from pyserve import RawAddr
from pyderive import dataclass

from . import BaseClient, Message

#** Variables **#
__all__ = ['UdpClient', 'TcpClient']

#** Classes **#

class SocketPool(Pool[socket.socket]):
    pass

@dataclass(slots=True)
class Client(BaseClient, ABC):
    """
    Baseclass Socket-Based DNS Client Implementation
    """
    addresses:  List[RawAddr]
    block_size: int           = 65535
    pool_size:  Optional[int] = None
    expiration: Optional[int] = 15
    timeout:    int           = 10

    def __post_init__(self):
        self.pool = SocketPool(
            factory=self.newsock,
            cleanup=self.cleanup,
            max_size=self.pool_size,
            expiration=self.expiration)

    @abstractmethod
    def newsock(self) -> socket.socket:
        """
        spawn new socket object to make request

        :return: new socket object
        """
        raise NotImplementedError

    @abstractmethod
    def cleanup(self, sock: socket.socket):
        """
        close and clean an existing socket object

        :param sock: socket object
        """
        raise NotImplementedError

    def pickaddr(self) -> RawAddr:
        """
        pick random address from list of addresses

        :return: random dns address to make request
        """
        return random.choice(self.addresses)

    def drain(self):
        """
        drain socket pool
        """
        self.pool.drain()

class UdpClient(Client):
    """
    Simple UDP Socket DNS Client
    """

    def newsock(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        return sock

    def cleanup(self, sock: socket.socket):
        sock.close()

    def request(self, msg: Message) -> Message:
        with self.pool.reserve() as sock:
            # send request
            addr = self.pickaddr()
            data = msg.pack()
            sock.sendto(data, addr)
            # recieve response
            data, _ = sock.recvfrom(self.block_size)
            return Message.unpack(data)

class TcpClient(Client):
    """
    Simple TCP Socket DNS Client
    """

    def newsock(self) -> socket.socket:
        addr = self.pickaddr()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(addr)
        return sock

    def cleanup(self, sock: socket.socket):
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

    def request(self, msg: Message) -> Message:
        with self.pool.reserve() as sock:
            # send request
            data = msg.pack()
            data = len(data).to_bytes(2, 'big') + data
            sock.send(data)
            # recieve size of response
            sizeb = sock.recv(2)
            size  = int.from_bytes(sizeb, 'big')
            # read data from size
            data = sock.recv(size)
            return Message.unpack(data)

