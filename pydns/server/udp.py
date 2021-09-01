"""
generic UDP dns server implementation
"""
import sys
import socket
import asyncio
import logging
import traceback
from typing import Optional, Tuple

from . import Handler, Addr
from .. import DNSPacket, SerialCtx, QR, RCode
from ..exceptions import DNSException, NotImplemented

#** Variables **#
__all__ = []

#** Functions **#

def _logger(name: str, loglevel: int) -> logging.Logger:
    """
    spawn logging instance w/ the given loglevel
    :param name:     name of the logging instance
    :param loglevel: level of verbosity on logging instance
    """
    log = logging.getLogger(name)
    log.setLevel(loglevel)
    # spawn handler
    fmt     = logging.Formatter('[%(process)d] [%(name)s] [%(levelname)s] %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)
    handler.setLevel(loglevel)
    log.handlers.append(handler)
    return log

def _new_handler(
    num:       int,
    log:       logging.Logger,
    factory:   DNSPacket,
    handler:   Handler,
    interface: Optional[str] = None,
) -> asyncio.DatagramProtocol:
    """
    spawn new subclass of handler to handle incoming DNS packets
    :param num:       number assigned to handler when spawning multiple
    :param log:       logging instance used for debugging
    :param factory:   dns-class used to deserialize raw bytes
    :param handler:   function used to handle packets formed with factory
    :param interface: network interface to bind socket to
    :return:          new handler to handle dns packets
    """
    class NewHandler(_Handler):
        _num       = num
        _log       = log
        _factory   = factory
        _interface = None if interface is None else interface.encode('utf-8')

        def on_packet(self, pkt: DNSPacket, addr: Addr) -> Optional[DNSPacket]:
            return handler(pkt, addr)
    return NewHandler

#** Classes **#

class _Handler(asyncio.DatagramProtocol):
    """metaclass handler for incoming udp packets built for DNS"""
    _num:       int
    _log:       logging.Logger
    _factory:   DNSPacket
    _interface: Optional[bytes] = None

    def _on_error(self, e: Exception, pkt: DNSPacket, addr: Addr):
        """run on failure to handle packet/transport"""
        pkt.flags.qr = QR.Response
        pkt.flags.rcode = RCode.ServerFailure
        # handle EDNS response
        if pkt.additional:
            pkt.additional[0].content = None
        # edit pkt if error is DNS specific
        if isinstance(e, DNSException):
            pkt.flags.rcode = e.code
        # send error over transport
        self._ctx.reset()
        self._transport.sendto(pkt.to_bytes(self._ctx), addr)

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._ctx = SerialCtx()
        self._transport = transport
        # bind to given interface if given
        if self._interface is not None:
            sock = self._transport.get_extra_info('socket')
            sock.setsockopt(socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE, self._interface)

    def on_packet(self, req: DNSPacket, addr: Addr) -> Optional[DNSPacket]:
        raise NotImplementedError('on-packet handler not declared')

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """
        handle incoming dns-packet and send appropriate response

        :param data: raw-bytes being collected from client
        :parma addr: address request is coming from
        """
        # retrieve request object if possible
        try:
            self._ctx.reset()
            req = self._factory.from_bytes(data, self._ctx)
        except Exception as e:
            self._log.debug('(%s) failed to parse DNS: %s' % (addr[0], e))
            return
        # attempt to retrieve response
        try:
            res = self.on_packet(req, Addr(addr[0], addr[1]))
        except Exception as e:
            self._log.error('(%s) failed to handle packet: %s' % (addr[0], e))
            print('\n%s' % traceback.format_exc(), file=sys.stderr)
            self._on_error(e, req, addr)
            return
        # attempt to send response
        try:
            if res is not None:
                self._ctx.reset()
                self._transport.sendto(res.to_bytes(self._ctx), addr)
        except Exception as e:
            # log error and print traceback
            self._log.error('(%s) unable to send response: %s' % (addr[0], e))
            print('\n%s' % traceback.format_exc(), file=sys.stderr)
            self._on_error(e, req, addr)

class UDPServer:
    """complete DNS server used to handle and reply to packets"""

    def __init__(self,
        factory:   DNSPacket         = DNSPacket,
        handler:   Optional[Handler] = None,
        address:   Tuple[str, int]   = ('0.0.0.0', 53),
        interface: Optional[str]     = None,
        debug:     bool              = False,
    ):
        """
        :param factory:   dns packet factory
        :param handler:   optional override on class packet handler
        :param address:   address to bind server to
        :param interface: network interface used to send replies
        :param debug:     enable debugging if true
        """
        loglevel       = logging.DEBUG if debug else logging.INFO
        self.log       = _logger('dns.udp', loglevel)
        self.factory   = factory
        self.address   = address
        self.interface = interface
        self.handler   = self.handler if handler is None else handler

    def handler(self, pkt: DNSPacket, addr: Addr) -> Optional[DNSPacket]:
        """default handler just returns back an empty response w/ no answers"""
        raise NotImplemented('dns handler not implemented')

    def run_forever(self, threads: int = 5) -> asyncio.Future:
        """
        spawn dns server and start handling incoming packets
        :param threads: number of handlers spawned in parralel
        :return:        asyncio future object in charge of running server
        """
        loop      = asyncio.get_event_loop()
        endpoints = []
        for n in range(threads):
            handle = _new_handler(
                num=n,
                log=self.log,
                factory=self.factory,
                handler=self.handler,
                interface=self.interface
            )
            point = loop.create_datagram_endpoint(handle,
                local_addr=self.address, reuse_port=True, allow_broadcast=False)
            endpoints.append(point)
        # return gathered endpoints
        self.log.info('Serving DNS on %s port %d' % self.address)
        return asyncio.gather(*endpoints)
