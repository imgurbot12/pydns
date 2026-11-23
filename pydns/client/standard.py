"""
Standard UDP/TCP Client Implementations
"""
import random
import socket
from abc import ABC, abstractmethod
from typing import Generic, List, Optional, TypeVar

from pypool import AsyncPool
from pyserve import RawAddr, TcpAsyncClient, UdpAsyncClient
from pyderive import dataclass

from . import BaseClient, Message

#** Variables **#
__all__ = ['UdpClient', 'TcpClient']

P = TypeVar('P', bound=AsyncPool)

#** Classes **#

@dataclass(slots=True)
class Client(BaseClient, ABC, Generic[P]):
    """
    Base-class Socket-Based DNS Client Implementation
    """
    addresses:  List[RawAddr]
    block_size: int           = 8192
    pool_size:  Optional[int] = None
    expiration: Optional[int] = 15
    timeout:    int           = 10

    def __post_init__(self):
        self.pool: AsyncPool[P] = AsyncPool(
            factory=self.newsock,
            cleanup=self.cleanup,
            max_size=self.pool_size,
            expiration=self.expiration)

    @abstractmethod
    async def newsock(self) -> P:
        """
        Spawn new socket object to make request
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup(self, client: P):
        """
        Close and clean an existing socket object
        """
        raise NotImplementedError

    def pickaddr(self) -> RawAddr:
        """
        Pick random address from list of addresses
        """
        return random.choice(self.addresses)

    def drain(self):
        """
        Drain socket pool
        """
        self.pool.drain()

class UdpClient(Client[UdpAsyncClient]):
    """
    Simple UDP Socket DNS Client
    """

    async def newsock(self) -> UdpAsyncClient:
        #NOTE: As of py3.14, using the DatagramProtocol over
        # the new 'loop.sock_*' functions is a bazillion times
        # faster at scale for some reason. It's night and day.
        client = UdpAsyncClient(True)
        client.socket.settimeout(self.timeout)
        return client

    async def cleanup(self, client: UdpAsyncClient):
        client.close()

    async def request(self, msg: Message, addr: Optional[RawAddr] = None) -> Message:
        async with self.pool.reserve(discard_on=(socket.timeout, )) as client:
            # send request
            addr = addr or self.pickaddr()
            data = msg.pack()
            await client.sendto(data, addr)
            # receive response
            data, _ = await client.recvfrom(self.block_size)
            return Message.unpack(data, source=addr[0])

class TcpClient(Client[TcpAsyncClient]):
    """
    Simple TCP Socket DNS Client
    """

    async def newsock(self) -> TcpAsyncClient:
        addr   = self.pickaddr()
        client = TcpAsyncClient()
        client.socket.settimeout(self.timeout)
        await client.connect(addr)
        return client

    async def cleanup(self, client: TcpAsyncClient):
        client.close()

    async def request(self, msg: Message) -> Message:
        async with self.pool.reserve(discard_on=(socket.timeout, )) as client:
            # send request
            data = msg.pack()
            data = len(data).to_bytes(2, 'big') + data
            await client.send(data)
            # receive size of response
            sizeb = await client.recv(2)
            size  = int.from_bytes(sizeb, 'big')
            # read data from size
            data = await client.recv(size)
            addr = client.socket.getpeername()
            return Message.unpack(data, source=addr[0])

