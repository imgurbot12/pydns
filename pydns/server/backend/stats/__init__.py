"""
DNS Answer Statistics Backend Wrapper
"""
from abc import abstractmethod
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Protocol

from pyderive import dataclass, field
from pyderive.extensions.serde import Serde

from .. import Answers, Backend, RuleBackend
from .... import RType

#** Variables **#
__all__ = [
    'Stats',
    'StatStorage',
    'SqliteStatStore',
    'StatBackend',
]

#** Functions **#

def date_now() -> datetime:
    """
    generate current timestamp rounded to the hour
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
    def stats(self) -> List[Stats]:
        """
        list stats for each hour in the day (24 entries)
        """
        raise NotImplementedError

    @abstractmethod
    def count_authority(self, count: int = 1, now: Optional[datetime] = None):
        """
        update count for an authoritative answer
        """
        raise NotImplementedError

    @abstractmethod
    def count_question(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        """
        update count for number of questions serviced
        """
        raise NotImplementedError

    @abstractmethod
    def count_block(self, rtype: RType,
        count: int = 1, now: Optional[datetime] = None):
        """
        update count for number of questions blocked
        """
        raise NotImplementedError

    @abstractmethod
    def count_source(self, source: str,
        count: int = 1, now: Optional[datetime] = None):
        """
        update count for answers of specific sources
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

    def stats(self) -> List[Stats]:
        """
        retrieve statistics from storage
        """
        return self.storage.stats()

    def is_blocked(self, answers: Answers) -> bool:
        """
        determine if answer should be considered blocked
        """
        return answers.source in {RuleBackend.source, }

    def is_authority(self, domain: bytes) -> bool:
        """
        retrieve if item is authority and update stats
        """
        is_authority = self.backend.is_authority(domain)
        if is_authority:
            self.storage.count_authority()
        return is_authority

    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        retrieve answers and update statistics
        """
        answers = self.backend.get_answers(domain, rtype)
        if self.is_blocked(answers):
            self.storage.count_block(rtype)
        self.storage.count_question(rtype)
        self.storage.count_source(answers.forwarder or 'local')
        return answers

#** Import **#
from .sqlite import SqliteStatStore
