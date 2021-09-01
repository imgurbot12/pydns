"""
"""
import time
import random
import socket
import requests
from queue import Queue
from typing import List, Tuple, Optional

from .. import *
from . import BaseClient

#** Variables **#
__all__ = ['UDPClient']

#** Classes **#

class UDPClient(BaseClient):
    """connection pooled dns client over udp"""

    def __init__(self,
        addrs:     List[Tuple[str, int]],
        timeout:   int = 15,
        pool_size: int = -1
    ):
        """
        :param addrs:     addresses to connect for dns queries
        :param timeout:   timeout for an individual dns request
        :param pool_size: size of sock pool, client spawns conn everytime if -1
        """
        self.addrs   = addrs
        self.max     = pool_size
        self.timeout = timeout
        self.queue   = Queue(maxsize=pool_size) if pool_size > 0 else None
        # spawn all connectors for queue if a given pool-size is set
        if self.queue is not None:
            for _ in range(pool_size):
                self.queue.put_nowait(self._new_connector())

    def _new_connector(self) -> Tuple[socket.socket, SerialCtx, float]:
        """spawn new socket and serial-ctx"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        return sock, SerialCtx(), time.time()

    def _get_connector(self) -> Tuple[socket.socket, SerialCtx]:
        """retrieve socket from pool and SerialCtx or spawn a new ones"""
        # retrieve a new connector every time if pool is unlimited size
        if self.queue is None:
            return self._new_connector()
        # otherwise wait for an item from the queue
        sock, ctx, ts = self.queue.get()
        # close socket if created longer than timeout
        if (time.time() - ts) > self.timeout:
            sock.close()
            sock, ctx, _ = self._new_connector()
        # otherwise return recently used socket
        return sock, ctx

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
        for addr in self.addrs:
            # retrieve socket and SerialCtx
            sock, ctx = self._get_connector()
            try:
                # send and recieve packet
                sock.sendto(pkt.to_bytes(ctx), addr)
                raw, addr = sock.recvfrom(8192)
                # parse packet using ctx and return
                ctx.reset()
                return DNSPacket.from_bytes(raw, ctx)
            except socket.timeout:
                pass
            finally:
                if self.queue is not None:
                    self.queue.put_nowait((sock, ctx))
                else:
                    sock.close()

    def close(self):
        """close and socket connections in the active pool"""
        if self.queue is not None:
            while not self.queue.empty():
                sock, _ = self.queue.get()
                sock.close()

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
