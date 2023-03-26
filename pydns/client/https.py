"""
Web HTTP Based DNS Client
"""
from urllib.request import Request, urlopen
from dataclasses import dataclass
from typing import Optional

from . import BaseClient, Message

#** Variables **#
__all__ = ['HttpsClient']

#** Classes **#

@dataclass
class HttpsClient(BaseClient):
    url:     str           = 'https://cloudflare-dns.com/dns-query'
    timeout: Optional[int] = None

    def __post_init__(self):
        self.headers = {
            'Accept':       'application/dns-message',
            'Content-Type': 'application/dns-message'
        }

    def request(self, msg: Message) -> Message:
        """
        handle https specific dns request

        :param msg: request message
        :return:    response message
        """
        data    = msg.encode()
        req     = Request(self.url, data=data, headers=self.headers)
        res     = urlopen(req, timeout=self.timeout)
        content = res.read()
        if res.status != 200:
            raise RuntimeError(f'Invalid Response: {res.status} {content}')
        return Message.decode(content)

