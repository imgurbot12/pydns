"""
Standard UDP/TCP Client Implementations
"""
import random
import socket
from dataclasses import dataclass
from typing import List, Optional

from pypool import Pool
from pyserve import RawAddr

from . import BaseClient, Message

#** Variables **#
__all__ = ['UdpClient', 'TcpClient']

#** Classes **#

class SocketPool(Pool[socket.socket]):
    pass

@dataclass
class Client(BaseClient):
    addresses:  List[RawAddr]
    block_size: int           = 8192
    pool_size:  Optional[int] = None
    expiration: Optional[int] = None
    timeout:    int           = 30

    def __post_init__(self):
        self.pool = SocketPool(
            factory=self.newsock, 
            max_size=self.pool_size, 
            expiration=self.expiration)
    
    def newsock(self):
        raise NotImplementedError

    def pickaddr(self) -> RawAddr:
        """pick random address from list of addresses"""
        return random.choice(self.addresses)
    
    def drain(self):
        """drain socket pool"""
        self.pool.drain()

@dataclass
class UdpClient(Client):
   
    def newsock(self) -> socket.socket:
        """spawn new socket for the socket pool"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        return sock
    
#TODO: include some sort of UDP retry if response doesnt come back after timeout

    def request(self, msg: Message) -> Message:
        """
        send request to dns-server and recieve response
        """
        with self.pool.reserve() as sock:
            # send request
            addr = self.pickaddr()
            data = msg.encode()
            sock.sendto(data, addr)
            # recieve response
            data = sock.recv(self.block_size)
            return Message.decode(data)

class TcpClient(Client):

    def newsock(self) -> socket.socket:
        """spawn new socket for the socket pool"""
        addr = self.pickaddr()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(addr)
        return sock

    def request(self, msg: Message) -> Message:
        """
        send request to dns-server and recieve response
        """
        with self.pool.reserve() as sock:
            # send request
            data = msg.encode()
            data = len(data).to_bytes(2, 'big') + data
            sock.send(data)
            # recieve size of response
            sizeb = sock.recv(2)
            size  = int.from_bytes(sizeb, 'big')
            # read data from size
            data = sock.recv(size)
            return Message.decode(data)

