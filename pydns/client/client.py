"""
"""
import random
import socket
import requests
from queue import Queue
from typing import Tuple, Optional

from .. import *
from . import BaseClient

#** Variables **#
__all__ = ['UDPClient']

#** Classes **#

class UDPClient(BaseClient):
    """connection pooled dns client over udp"""

    def __init__(self, addr: Tuple[str, int], pool_size: int = -1):
        """
        :param addr:      address to connect for dns queries
        :param pool_size: size of sock pool, client spawns conn everytime if -1
        """
        self.addr     = addr
        self.max      = pool_size
        self.queue    = Queue(maxsize=pool_size) if pool_size else None
        self.cache    = [] if pool_size else None

    def _get_socket(self) -> Tuple[socket.socket, SerialCtx]:
        """retrieve socket from pool and SerialCtx or spawn a new ones"""
        if self.max > 0:
            if len(self.cache) < self.max:
                s   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(10)
                ctx = SerialCtx()
                self.cache.append((s, ctx))
                return (s, ctx)
            return self.queue.get()
        else:
            s   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ctx = SerialCtx()
            return (s, ctx)

    def query(self, *questions: Question) -> DNSPacket:
        """
        query the dns server over udp and return the response

        :param q:  list of questions to include in query
        :param fl: alternative flag configurations
        :return:   response from dns server
        """
        pkt = DNSPacket(
            id=random.randint(0, 65534),
            flags=Flags(qr=QR.Question, op=OpCode.Query, rd=True),
            questions=questions,
        )
        s, ctx = self._get_socket()
        try:
            # send and recieve packet
            s.sendto(pkt.to_bytes(ctx), self.addr)
            raw, addr = s.recvfrom(8192)
            # parse packet using ctx and return
            ctx.reset()
            return DNSPacket.from_bytes(raw, ctx)
        finally:
            if self.max > 0:
                self.queue.put_nowait((s, ctx))
            else:
                s.close()

    def close(self):
        """close and socket connections in the active pool"""
        if self.cache:
            for s in self.cache:
                s.close()

class HTTPClient:

    def __init__(self, url: str = 'https://cloudflare-dns.com/dns-query'):
        self.url     = url
        self.session = requests.Session()
        self.session.headers = {
            'Accept':       'application/dns-message',
            'Content-Type': 'application/dns-message'
        }

    def query(self, *q: Question) -> DNSPacket:
        """
        query the dns server over https and return response

        :param q:  list of questions to include in query
        :param fl: alternative flag configurations
        :return:   response from dns server
        """
        ctx = SerialCtx()
        pkt = DNSPacket(
            id=random.randint(0, 65534),
            flags=Flags(qr=QR.Question, op=OpCode.Query, rd=True),
            questions=q,
        )
        r = self.session.post(self.url, data=pkt.to_bytes(ctx))
        print(r.status_code, r.content)
