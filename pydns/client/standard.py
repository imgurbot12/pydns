"""
Standard UDP/TCP Client Implementations
"""
import asyncio
import random
from abc import ABC, abstractmethod
from typing import Generic, List, Optional, TypeVar, Union

from pypool import AsyncPool
from pyserve import RawAddr, TcpAsyncClient, UdpAsyncClient
from pyderive import dataclass

from . import BaseClient, Message

#** Variables **#
__all__ = ['UdpClient', 'TcpClient', 'HybridClient']

P = TypeVar('P', bound=Union[TcpAsyncClient, UdpAsyncClient])

#** Functions **#

def timeout_error(
    host: str, req: Message, timeout: Optional[float]) -> TimeoutError:
    """
    Generate a more descriptive timeout error
    """
    quest = ', '.join([f'{q.name} ({q.qtype.name})' for q in req.questions])
    return TimeoutError(f'{host} timed out on {quest} after {timeout}s')

async def tcp_request(
    client: TcpAsyncClient,
    req:    Message,
    raddr:  Optional[RawAddr] = None
) -> Message:
    """
    Send DNS request using async TCP client
    """
    data = req.pack()
    data = len(data).to_bytes(2, 'big') + data
    addr = raddr or client.socket.getpeername()
    try:
        await client.send(data)
        # receive size of response
        sizeb = await client.recv(2)
        size  = int.from_bytes(sizeb, 'big')
        # read data from size
        data = await client.recv(size)
        return Message.unpack(data, source=addr[0])
    except asyncio.TimeoutError:
        raise timeout_error(addr[0], req, client.timeout) from None

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

    async def cleanup(self, client: P):
        """
        Close and clean an existing socket object
        """
        client.close()

    def pickaddr(self) -> RawAddr:
        """
        Pick random address from list of addresses
        """
        return random.choice(self.addresses)

    async def drain(self):
        """
        Drain socket pool
        """
        await self.pool.drain()

class UdpClient(Client[UdpAsyncClient]):
    """
    Simple UDP Socket DNS Client
    """

    async def newsock(self) -> UdpAsyncClient:
        #NOTE: As of py3.14, using the DatagramProtocol over
        # the new 'loop.sock_*' functions is a bazillion times
        # faster at scale for some reason. It's night and day.
        client = UdpAsyncClient(self.timeout, True)
        return client

    async def request(self, msg: Message, addr: Optional[RawAddr] = None) -> Message:
        async with self.pool.reserve(
            discard_on=(asyncio.TimeoutError, )) as client:
            addr = addr or self.pickaddr()
            data = msg.pack()
            try:
                await client.sendto(data, addr)
                data, _ = await client.recvfrom(self.block_size)
                return Message.unpack(data, source=addr[0])
            except asyncio.TimeoutError:
                raise timeout_error(addr[0], msg, client.timeout) from None

class TcpClient(Client[TcpAsyncClient]):
    """
    Simple TCP Socket DNS Client
    """

    async def newsock(self) -> TcpAsyncClient:
        addr   = self.pickaddr()
        client = TcpAsyncClient(timeout=self.timeout)
        await client.connect(addr)
        return client

    async def request(self, msg: Message) -> Message:
        async with self.pool.reserve(
            discard_on=(asyncio.TimeoutError, BrokenPipeError)) as client:
            return await tcp_request(client, msg)

class HybridClient(UdpClient):
    """
    UDP Client with TCP Fallback on Timeout
    """

    async def request(self, msg: Message, addr: Optional[RawAddr] = None) -> Message:
        addr = addr or self.pickaddr()
        try:
            return await super().request(msg, addr)
        except TimeoutError:
            async with TcpAsyncClient(self.timeout) as client:
                await client.connect(addr)
                return await tcp_request(client, msg, addr)
