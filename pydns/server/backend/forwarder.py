"""
Backend Recursive Client-Forwarder Extension
"""
from dataclasses import dataclass
from typing import ClassVar

from . import Answers, Backend
from ...client import BaseClient
from ... import RType, Answer, Question

#** Variables **#
__all__ = ['Forwarder']

#** Classes **#

@dataclass(repr=False)
class Forwarder(Backend):
    """
    Recursive Dns-Client Lookup Forwarder when Backend returns no Results
    """
    __slots__ = ('backend', 'client')
    source: ClassVar[str] = 'Forwarder'
    recursion_available: ClassVar[bool] = True

    backend: Backend
    client:  BaseClient

    def is_authority(self, domain: bytes) -> bool:
        return self.backend.is_authority(domain)

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        query for answers w/ client if base-backend returns empty result
        """
        answers, source = self.backend.get_answers(domain, rtype)
        if not answers:
            source  = self.source
            message = self.client.query(Question(domain, rtype))
            answers.extend(message.answers)
            answers.extend(message.authority)
            answers.extend([
                a for a in message.additional if isinstance(a, Answer)])
        return Answers(answers, source)
