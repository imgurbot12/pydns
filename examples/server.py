"""
Simple Example Server Implementation
"""
import logging

from pyserve import listen_udp_threaded

from pydns.client import UdpClient
from pydns.server import Session
from pydns.server.backend import MemoryBackend, Forwarder, Cache

# declare and configure server address and forwarding client addresses
server_addr  = ('127.0.0.1', 53)
client_addrs = [('8.8.8.8', 53)]

# prepare simple memory backend as base provider
backend = MemoryBackend()
backend.save_domain(b'example.com', {
    'A':   [{'ip': '1.2.3.4'}],
    'MX':  [{'preference': 1, 'exchange': b'mx.example.com'}],
    'SOA': [{
        'mname': b'mname.example.com', 
        'rname': b'rname.example.com', 
        'serialver': 1, 
        'refresh': 2, 
        'retry': 3, 
        'expire': 4, 
        'minimum': 5
    }]
})

# wrap memory backend w/ client forwarder 
client  = UdpClient(client_addrs)
backend = Forwarder(backend, client)

# wrap backend w/ cache to cache forwarded content
backend = Cache(backend)

# configure optional logger for session implementaion
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('myserver')
logger.setLevel(logging.INFO)

# launch server and run forever using pyserve
listen_udp_threaded(server_addr, Session, backend=backend, logger=logger)
