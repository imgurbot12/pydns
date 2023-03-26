"""
Universal Codec Types
"""
from abc import abstractmethod
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, Protocol, ClassVar, Callable, Any, Union, Type
from typing_extensions import runtime_checkable

#** Variable **#
__all__ = [
    'Context',

    'Codec',
    'Int',
    'SizedBytes',
    'IpAddress',
    'Domain',
]

#** Classes **#

@dataclass
class Context:
    """Encoding/Decoding Context Tracking"""
    index: int = 0
    index_to_domain: Dict[int, bytes] = field(default_factory=dict)
    domain_to_index: Dict[bytes, int] = field(default_factory=dict)

    def slice(self, raw: bytes, length: int) -> bytes:
        end  = self.index + length
        data = raw[self.index:end]
        self.index = end
        return data

    def save_domain(self, domain: bytes, index: int):
        self.index_to_domain[index] = domain
        self.domain_to_index[domain] = index

@runtime_checkable
class Codec(Protocol):
    """Encoding/Decoding Codec Protocol"""
    base_type: type

    @classmethod
    @abstractmethod
    def encode(cls, ctx: Context, value: Any) -> bytes:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def decode(cls, ctx: Context, raw: bytes) -> Any:
        raise NotImplementedError

class Int(Codec):
    size: ClassVar[int]
    wrap: ClassVar[Callable[[int], Any]]
    base_type: type = int
    
    def __class_getitem__(cls, s: Union[int, tuple]) -> Type['Int']:
        """generate custom Int subclass with the given options"""
        size = s if isinstance(s, int) else s[0]
        wrap = s[1] if isinstance(s, tuple) and len(s) > 1 else lambda x: x
        name = s[2] if isinstance(s, tuple) and len(s) > 2 else cls.__name__
        assert size % 8 == 0, 'size must be multiple of eight'
        cname = f'{name}[{size}]'
        return type(cname, (cls, ), {'size': size // 8, 'wrap': wrap})

    @classmethod
    def encode(cls, ctx: Context, i: int) -> bytes:
        ctx.index += cls.size
        return i.to_bytes(cls.size, 'big')

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> int:
        data = ctx.slice(raw, cls.size)
        size = cls.size * 8
        assert len(data) == cls.size, f'len(bytes)[{len(data)}] != Int[{size}]'
        value = int.from_bytes(data, 'big')
        return cls.wrap(value)

class IpAddress(Codec):
    size:      int
    base_type: Union[Type[IPv4Address], Type[IPv6Address]]

    def __class_getitem__(cls, iptype: str) -> Type['IpAddress']:
        assert iptype in ('ipv4', 'ipv6'), 'invalid ipaddress type'
        size = 4 if iptype == 'ipv4' else 16
        addr = IPv4Address if iptype == 'ipv4' else IPv6Address
        return type(f'IPv{iptype[-1]}', (cls, ), {
            'size': size, 
            'base_type': addr
        })

    @classmethod
    def encode(cls, ctx: Context, ip: Union[str, bytes]) -> bytes:
        packed = cls.base_type(ip).packed
        ctx.index += len(packed)
        return packed

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> Union[IPv4Address, IPv6Address]:
        data = ctx.slice(raw, cls.size)
        return cls.base_type(data)

class SizedBytes(Codec):
    hint:      Type[Codec] = Int[32]
    base_type: type        = bytes
    
    def __class_getitem__(cls, hint: int) -> Type['SizedBytes']:
        codec = Int[hint]
        return type('SizedBytes[{hint!r}]', (cls, ), {'hint': codec})

    @classmethod
    def encode(cls, ctx: Context, content: bytes) -> bytes:
        hint = cls.hint.encode(ctx, len(content))
        ctx.index += len(content)
        return hint + content

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> bytes:
        hint = cls.hint.decode(ctx, raw)
        return ctx.slice(raw, hint)

class Domain(Codec):
    ptr_mask:  int  = 0xC0
    base_type: type = bytes

    @classmethod
    def encode(cls, ctx: Context, domain: bytes) -> bytes:
        encoded = bytearray()
        while domain:
            # check if ptr is an option for remaining domain
            if domain in ctx.domain_to_index:
                index      = ctx.domain_to_index[domain]
                pointer    = index.to_bytes(2, 'big')
                encoded   += bytes((pointer[0] | cls.ptr_mask, pointer[1]))
                ctx.index += 2 
                return bytes(encoded)
            # save partial domain as index
            ctx.save_domain(domain, ctx.index)
            # handle components of name
            split        = domain.split(b'.', 1)
            name, domain = split if len(split) == 2 else (split[0], b'')
            encoded     += len(name).to_bytes(1, 'big') + name
            ctx.index   += 1 + len(name)
        # write final zeros before returning final encoded data
        encoded   += b'\x00'
        ctx.index += 1
        return bytes(encoded)

    @classmethod
    def decode(cls, ctx: Context, raw: bytes) -> bytes:
        domain = []
        while True:
            # check for length of domain component
            length     = raw[ctx.index]
            ctx.index += 1
            if length == 0:
                break
            # check if name is a pointer
            if length & cls.ptr_mask == cls.ptr_mask:
                name  = bytes((length ^ cls.ptr_mask, raw[ctx.index]))
                index = int.from_bytes(name, 'big')
                base  = ctx.index_to_domain[index]
                domain.append((base, None))
                ctx.index += 1
                break
            # slice name from bytes and updated counter
            idx  = ctx.index - 1
            name = ctx.slice(raw, length)
            domain.append((name, idx))
        # save domain components
        for n, (name, index) in enumerate(domain, 0):
            if index is None:
                continue
            subname = b'.'.join(name for name, _ in domain[n:])
            ctx.save_domain(subname, index)
        return b'.'.join(name for name, _ in domain)
