"""
dns server library for handling incoming packets over udp
"""
from collections import namedtuple
from typing import Tuple, Callable

#** Variables **#
__all__ = ['Addr', 'Handler', 'UDPServer']

#: udp address schema
Addr: Tuple[str, int] = namedtuple('Addr', ['host', 'port'])

#: dns packet handler function type definition
Handler = Callable[['DNSPacket', Addr], None]

from .server import UDPServer
