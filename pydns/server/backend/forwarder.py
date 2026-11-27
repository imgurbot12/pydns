"""
Backend Recursive Client-Forwarder Extension
"""
from typing import ClassVar

from . import Answers, Backend
from ...client import BaseClient
from ... import RType, Answer, Question

#** Variables **#
__all__ = ['Forwarder']

#** Classes **#

class Forwarder(Backend):
    """
    Recursive DNS-Client Lookup Forwarder when Backend returns no Results
    """
    __slots__ = ('backend', 'client')

    source: ClassVar[str] = 'Forwarder'

    def __init__(self, backend: Backend, client: BaseClient):
        self.backend = backend
        self.client  = client

    def recursion_available(self) -> bool:
        return True

    async def is_authority(self, domain: bytes) -> bool:
        return await self.backend.is_authority(domain)

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        Query for answers with client if base-backend returns empty result
        """
        answers = await self.backend.get_answers(domain, rtype)
        if not answers.answers and answers.rcode is None:
            message = await self.client.query(Question(domain, rtype))
            answers.source = self.source
            answers.answers.extend(message.answers)
            answers.answers.extend(message.authority)
            answers.answers.extend([
                a for a in message.additional if isinstance(a, Answer)])
            answers.forwarder = message.source
        return answers

