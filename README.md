pydns
------

[![PyPI version](https://img.shields.io/pypi/v/pydns3?style=for-the-badge)](https://pypi.org/project/pydns3/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydns3?style=for-the-badge)](https://pypi.org/project/pydns3/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://github.com/imgurbot12/pydns/blob/master/LICENSE)
[![Made with Love](https://img.shields.io/badge/built%20with-%E2%99%A5-orange?style=for-the-badge)](https://github.com/imgurbot12/pydns)

Simple Python DNS Library. DNS Packet-Parsing/Client/Server

### Installation

```
pip install pydns3
```

### Examples

Packet Parsing

```python
from pydns import Message

raw = \
  b"\x5c\x7d\x81\x80\x00\x01\x00\x00\x00\x01\x00\x01\x03\x77\x77\x77" \
  b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x01" \
  b"\xc0\x10\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x26\x03\x6e\x73\x31" \
  b"\xc0\x10\x09\x64\x6e\x73\x2d\x61\x64\x6d\x69\x6e\xc0\x10\x1e\xe8" \
  b"\x04\x72\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00" \
  b"\x00\x3c\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"

req = Message.unpack(raw)
print(req)
```

Client

```python
from pydns import Question, RType
from pydns.client import UdpClient

client = UdpClient([('8.8.8.8', 53)])

query = Question(b'www.google.com', RType.AAAA)
res   = client.query(query)
print(res)
```

Simple Server

```python
import logging

from pyserve import listen_udp_threaded

from pydns.client import UdpClient
from pydns.server import Server
from pydns.server.backend import MemoryBackend, Forwarder, Cache

# declare and configure server address and forwarding client addresses
server_addr  = ('127.0.0.1', 53)
client_addrs = [('8.8.8.8', 53)]

# prepare simple memory backend as base provider
backend = MemoryBackend()
backend.save_domain_dict(b'example.com', {
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

# configure optional logger for server implementaion
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('myserver')
logger.setLevel(logging.INFO)

# launch server and run forever using pyserve
listen_udp_threaded(server_addr, Server, backend=backend, logger=logger)
```
