"""
Use PyDNS as a standard DNS Parsing Library
"""
from pydns.codec import Context
from pydns.message import Message

raw = \
b"\x5c\x7d\x81\x80\x00\x01\x00\x00\x00\x01\x00\x01\x03\x77\x77\x77" \
b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x01" \
b"\xc0\x10\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x26\x03\x6e\x73\x31" \
b"\xc0\x10\x09\x64\x6e\x73\x2d\x61\x64\x6d\x69\x6e\xc0\x10\x1e\xe8" \
b"\x04\x72\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00" \
b"\x00\x3c\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"

ctx = Context()
req = Message.decode(raw)
print(req)