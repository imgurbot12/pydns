"""
baseclass udp implementation using threadpool connection handling
"""
import sys
import time
import socket
import threading
import traceback
from collections import namedtuple
from typing import Tuple, Callable, Optional
from concurrent.futures import Future, ThreadPoolExecutor

from . import Addr

#** Variables **#
__all__ = ['Handler', 'Server']

#** Classes **#

class Handler:
    """udp connection handler baseclass"""

    def __init__(self, sock: socket.socket):
        self.connection_made(sock)

    def connection_made(self, transport: socket.socket):
        """pass socket object on start of handler"""

    def datagram_received(self, data: bytes, addr: Addr):
        """handle incoming data from specified address"""

    def error_received(self, err: Exception):
        """handle error on packet handling"""

class Server:
    """basic thread-pool udp server implementation"""

    def __init__(self,
        addr:             Addr,
        handler_factory:  Handler,
        threads:          int = 5,
        **kwargs
    ):
        """
        :param addr:            address for udp server
        :param handler_factory: udp handler factory
        :param threads:         number of threads to use in pool
        :param kwargs:          additional server settings
        """
        if not issubclass(handler_factory, Handler):
            raise TypeError('handler_factory must be subclass of Handler')
        default = {
            'recv':            2048,
            'reuse_port':      False,
            'broadcast':       False,
            'print_traceback': False,
        }
        self.addr     = addr
        self.factory  = handler_factory
        self._pool    = ThreadPoolExecutor(max_workers=threads)
        self._kw      = {**default, **kwargs}
        self._s       = None
        self._running = False
        # ensure that all keys in kwargs are valid
        for key in kwargs:
            if key not in default:
                raise ValueError('no such argument: %s' % key)

    def _future_cb(self, future: Future, handler: Handler):
        """check if error in response and run error-handler"""
        err = future.exception()
        if err is not None:
            # run exception handler
            handler.error_received(err)
            # print traceback for logs if enabled
            if self._kw['print_traceback']:
                tb  = ''.join(traceback.format_tb(err.__traceback__))
                print('Traceback (most recent call last):\n%s%s: %s' % (
                    ''.join(traceback.format_tb(err.__traceback__)),
                    err.__class__.__name__,
                    err.args[0],
                ), file=sys.stderr)

    def _listen(self) -> socket.socket:
        """generate new udp socket"""
        # open socket to listen for requests
        self._s = socket.socket(socket.AF_INET,
            socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if self._kw['reuse_port']:
            self._s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if self._kw['broadcast']:
            self._s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._s.bind(self.addr)
        # listen for messages from sock
        recv = self._kw['recv']
        while self._running:
            handler = self.factory(self._s)
            data, addr = self._s.recvfrom(recv)
            if not data:
                continue
            addr   = Addr(*addr)
            future = self._pool.submit(handler.datagram_received, data, addr)
            future.add_done_callback(lambda x: self._future_cb(x, handler))
        # shutdown set running to false
        self._s.close()

    def _shutdown(self):
        """set shutdown and force blocking socket to close by sending packet"""
        self._running = False
        # send socket request
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'', self.addr)
        # shutdown thread pool
        self._pool.shutdown(wait=False)

    def on_start(self):
        """run on server startup"""

    def on_shutdown(self):
        """run on server shutdown"""

    def run_forever(self):
        """run the server forever (a really long time)"""
        if self._running:
            raise RuntimeError('server already running!')
        try:
            self.on_start()
            self._running = True
            self._listen()
        finally:
            self._running = False
            # ensure socket closes
            if self._s is not None:
                self._s.close()
            # complete shutdown functions
            self.on_shutdown()
            self._pool.shutdown(wait=False)

    def wait_shutdown(self):
        """wait until shutdown"""
        while self._running:
            time.sleep(0.25)

    def start(self):
        """spawn server as a daemonized thread"""
        self._t = threading.Thread(target=self.run_forever, name='dns.server')
        self._t.daemon = True
        self._t.start()

    def stop(self):
        """stop daemonized server"""
        self._shutdown()
        self.wait_shutdown()
