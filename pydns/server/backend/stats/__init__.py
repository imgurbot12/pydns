"""
DNS Answer Statistics Backend Wrapper
"""
from abc import abstractmethod
from datetime import datetime, timedelta
from typing import ClassVar, Dict, List, Optional, Protocol

from pyderive import dataclass, field
from pyderive.extensions.serde import Serde

from .. import Answers, Backend, RuleBackend
from .... import RType

#** Variables **#
__all__ = [
    'Stats',
    'StatStorage',
    'StatStoreDB',
    'StatBackend',
]

#** Functions **#

def date_now() -> datetime:
    """
    Generate current timestamp rounded to the hour
    """
    now = datetime.now()
    return now.replace(minute=0, second=0, microsecond=0)

#** Classes **#

class Stats(Serde):
    """
    Statistics Measurement
    """
    date:            datetime
    total_queries:   int = 0
    blocked_queries: int = 0
    with_authority:  int = 0
    query_counts:    Dict[RType, int] = field(default_factory=dict)
    query_sources:   Dict[str, int]   = field(default_factory=dict)

    @classmethod
    def new(cls) -> 'Stats':
        return cls(date_now())

class StatStorage(Protocol):
    """
    Statistics Storage Backend
    """

    @abstractmethod
    async def stats(self, span: timedelta = timedelta(hours=24)) -> List[Stats]:
        """
        List stats for each hour in the day (24 entries)
        """
        raise NotImplementedError

    @abstractmethod
    async def count_authority(self, count: int = 1, now: Optional[datetime] = None):
        """
        Update count for an authoritative answer
        """
        raise NotImplementedError

    @abstractmethod
    async def count_question(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        """
        Update count for number of questions serviced
        """
        raise NotImplementedError

    @abstractmethod
    async def count_block(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        """
        Update count for number of questions blocked
        """
        raise NotImplementedError

    @abstractmethod
    async def count_source(self, source: str,
        count: int = 1, now: Optional[datetime] = None):
        """
        Update count for answers of specific sources
        """
        raise NotImplementedError

@dataclass(slots=True, repr=False)
class StatBackend(Backend):
    """
    Statistics Calculator Backend
    """
    source: ClassVar[str] = 'Statistics'

    backend: Backend
    storage: StatStorage

    async def stats(self, span: timedelta = timedelta(hours=24)) -> List[Stats]:
        """
        Retrieve statistics from storage
        """
        return await self.storage.stats(span)

    def is_blocked(self, answers: Answers) -> bool:
        """
        Determine if answer should be considered blocked
        """
        return answers.source in {RuleBackend.source, }

    async def is_authority(self, domain: bytes) -> bool:
        """
        Retrieve if item is authority and update stats
        """
        is_authority = await self.backend.is_authority(domain)
        if is_authority:
            await self.storage.count_authority()
        return is_authority

    async def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        Retrieve answers and update statistics
        """
        answers = await self.backend.get_answers(domain, rtype)
        if self.is_blocked(answers):
            await self.storage.count_block(rtype)
        await self.storage.count_question(rtype)
        await self.storage.count_source(answers.forwarder or 'local')
        return answers

#** Import **#
from .database import StatStoreDB
