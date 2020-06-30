"""
dns server implementation using udp server baseclass
"""
import logging
from typing import Callable, Optional

from . import udp, Handler
from .. import DNSPacket, QR, RCode, SerialCtx

#** Variables **#
__all__ = ['UDPServer']

#** Functions **#

def _make_logger(name: str, loglevel: int) -> logging.Logger:
    """generate logger for library"""
    logger    = logging.getLogger(name)
    c_handler = logging.StreamHandler()
    c_format  = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    c_handler.setLevel(logging.DEBUG)
    c_handler.setFormatter(c_format)
    logger.setLevel(loglevel)
    logger.addHandler(c_handler)
    return logger

#** Classes **#

class _Handler(udp.Handler):
    """basic dns handler class"""
    log:     logging.Logger
    handler: Handler

    def connection_made(self, transport):
        self.transport = transport
        self.ctx       = SerialCtx()
        self.addr      = None
        self.pkt       = None

    def datagram_received(self, data: bytes, addr: udp.Addr):
        # get packet
        self.ctx.reset()
        self.addr = addr
        self.pkt  = DNSPacket.from_bytes(data, self.ctx)
        # update flags for response
        self.pkt.flags.qr = QR.Response
        self.pkt.recursion_available = True
        # handle EDNS response
        if self.pkt.additonal:
            self.pkt.additonal[0].content = None
        # run packet handler
        self.handler(self.pkt)
        # attempt to send response
        self.ctx.reset()
        self.transport.sendto(self.pkt.to_bytes(self.ctx), addr)

    def error_received(self, err: Exception):
        # log error
        self.log.error(err)
        # attempt to send failure response if packet was parsed
        if self.pkt is not None:
            self.ctx.reset()
            self.pkt.flags.rcode = RCode.ServerFailure
            self.transport.sendto(self.pkt.to_bytes(self.ctx), self.addr)

class UDPServer(udp.Server):
    """dns server instance"""

    def __init__(self, addr: udp.Addr, handle: Optional[Handler] = None, **kw):
        """
        :param addr:   address server will bind to
        :param handle: dns packet handle function
        :param kw:     additional server arguments
        """
        self.log = _make_logger('dns.udp', logging.INFO)
        class Handler(_Handler):
            log     = self.log
            handler = handle or self.handle
        super().__init__(addr, Handler, **kw)

    def handle(self, pkt: DNSPacket):
        pass
