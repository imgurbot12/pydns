import signal
# import uvloop
import asyncio

# uvloop.install()

from dns import DNSPacket
from dns.const import QR, QType, SerialCtx
from dns.records import A, AAAA, SOA, TXT, CNAME, ResourceRecord

#** Classes **#

class Handler:

    def connection_made(self, transport):
        self._ctx = SerialCtx()
        self.transport = transport

    def datagram_received(self, data, addr):
        # parse packet and update to convert into response
        self._ctx.reset()
        pkt = DNSPacket.from_bytes(data, self._ctx)
        pkt.flags.qr = QR.Response
        pkt.flags.recursion_available = True
        # build ip response if A-request
        if pkt.questions[0].qtype == QType.A:
            pkt.answers.append(
                ResourceRecord(
                    name=pkt.questions[0].name,
                    ttl=1,
                    content=A('1.2.3.4'),
                )
            )
        # handle EDNS response
        if pkt.additonal:
            pkt.additonal[0].content = None
        # build and send response
        self._ctx.reset()
        self.transport.sendto
        self.transport.sendto(pkt.to_bytes(self._ctx), addr)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass

def start_server(loop, addr):
    t = asyncio.Task(loop.create_datagram_endpoint(Handler, local_addr=addr))
    transport, server = loop.run_until_complete(t)
    return transport

#** Start **#

def main():
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, loop.stop)
    server = start_server(loop, ('127.0.0.1', 53))
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()

import cProfile

cProfile.run('main()', filename='report.prof')
