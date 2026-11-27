"""
Single Flight Pattern Backend Abstraction
"""
from copy import deepcopy
from typing import ClassVar, Optional, TypeVar

from pyserve.utils import FlightSrc, SingleFlight as FlightManager

from . import Answers, Backend, RType

#** Variables **#
__all__ = ['SingleFlight']

T = TypeVar('T')

#** Classes **#

class SingleFlight(Backend):
    """
    Single-Flight Pattern Backend Wrapper

    Ensures a single lookup for a specific record
    only executes once at any given time.
    """
    source: ClassVar[str] = 'SingleFlight'

    __slots__ = ('backend', 'manager', 'wrap_label', )

    def __init__(self,
        backend:    Backend,
        manager:    Optional[FlightManager] = None,
        wrap_label: Optional[bool]          = True,
    ):
        self.backend             = backend
        self.manager             = manager or FlightManager()
        self.wrap_label          = wrap_label

    def recursion_available(self) -> bool:
        return self.backend.recursion_available()

    async def is_authority(self, domain: bytes) -> bool:
        task = self.backend.is_authority(domain)
        return await self.manager.do(f'is_authority:{domain}', task)

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        key          = f'get_answers:{domain}:{rtype.name}'
        task         = self.backend.get_answers(domain, rtype)
        answers, src = await self.manager.do_labeled(key, task)
        if self.wrap_label and src == FlightSrc.FOLLOWER:
            answers = deepcopy(answers)
            answers.source_label = f'{self.source}({answers.source})'
        return answers

    async def count_blocked(self) -> int:
        task = self.backend.count_blocked()
        return await self.manager.do('count_blocked', task)
