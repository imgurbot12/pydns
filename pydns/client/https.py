"""
Web HTTPS Based DNS Client
"""
from typing import Optional

from httpx import AsyncClient
from pyderive import dataclass

from . import BaseClient, Message

#** Variables **#
__all__ = ['HttpsClient']

#** Classes **#

@dataclass(slots=True)
class HttpsClient(BaseClient):
    """
    Simple DNS over HTTPS Client Implementation
    """
    url:     str           = 'https://cloudflare-dns.com/dns-query'
    timeout: Optional[int] = None

    def __post_init__(self):
        self.client = AsyncClient(
            timeout=self.timeout,
            headers={
                'User-Agent':   'PyDNS/0.0.1',
                'Accept':       'application/dns-message',
                'Content-Type': 'application/dns-message'
            },
        )

    async def request(self, msg: Message) -> Message:
        """
        Handle HTTPS specific DNS request
        """
        data    = msg.pack()
        res     = await self.client.post(self.url, content=data)
        content = await res.aread()
        if res.status_code != 200:
            raise RuntimeError(f'Invalid Response: {res.status_code} {content}')
        return Message.unpack(content, source=self.url)

