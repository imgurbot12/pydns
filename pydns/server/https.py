"""
dns server implementation for dns-over-https
"""
import socket
import logging
import asyncio
from sanic import Sanic
from sanic import request
from sanic import response
from concurrent.futures import ThreadPoolExecutor

from . import Addr, Handler
from .. import DNSPacket, QR, RCode, SerialCtx

#** Variables **#
__all__ = []

CONTENT_TYPE = 'application/dns-message'

#** Classes **#

class Handler:
    """https connection handler baseclass"""

    def __init__(self):
        self.connection_made()

    def connection_made(self):
        """run function on connection made"""

    def request_received(self, req: Request):
        """handle incoming data from connection"""

    def error_received(self, err: Exception):
        """handle error on request"""

class Server:

    def __init__(self,
        addr:            Addr,
        handle:          Handler,
        threads:         int  = 5,
        reuse_port:      bool = False,
        print_traceback: bool = False,
    ):
        """
        :param addr:            address web-server is assigned to
        :param handle:          dns-packet handler function
        :param threads:         number of threads in worker-pool
        :param reuse_port:      reuse port on socket in enabled
        :param print_traceback: print handler exceptions if enabled
        """
        self._pool = ThreadPoolExecutor(max_workers=threads)
        self._app  = Sanic('dns.https')
        self._kw   = {
            'reuse_port':      reuse_port,
            'print_traceback': print_traceback
        }

    async def _handler(self, req: request.Request) -> response.HTTPResponse:
        """handle inbound web-requests for dns-packets"""
        # check content-type
        if req.headers['Content-Type'] != CONTENT_TYPE:
            return response.empty(status=400)
        # run handler using thread-pool executor
        handler = Handler()
        loop    = asyncio.get_event_loop()
        future  = loop.run_in_executor(self._pool,
                    handler.request_received, req)
        print(future)

    def _future_cb(self, future: Future, handler: Handler):
        """check if error in response and run error-handler"""
        err = future.exception()
        if err is not None:
            # print traceback for logs if enabled
            if self._kw['print_traceback']:
                tb  = ''.join(traceback.format_tb(err.__traceback__))
                print('Traceback (most recent call last):\n%s%s: %s' % (
                    ''.join(traceback.format_tb(err.__traceback__)),
                    err.__class__.__name__,
                    err.args[0],
                ), file=sys.stderr)
            # run exception handler
            handler.error_received(err)

    def _listen(self):
        """spawn application listener w/ customised socket"""
        # open socket to listen for requests
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self._kw['reuse_port']:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(self.addr)
        # attach web-handler to sanic
        @self._app.get('/dns-query')
        def handle(req):
            return self._handler(req)
        # start listener for web-service
        app.run(s=s)

#** Init **#

# override sanic logging formats

fmt = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
for handler in logging.getLogger('sanic.access').handlers:
    handler.setFormatter(fmt)
