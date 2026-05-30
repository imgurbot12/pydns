"""
DNS Answer Statistics Backend Wrapper
"""
import dbm
import struct
from abc import abstractmethod
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Protocol, cast
from typing_extensions import MutableMapping

from pyderive import dataclass, field
from pyderive.extensions.serde import Serde

from . import Answers, Backend, RuleBackend
from ... import RType

#** Variables **#
__all__ = [
    'Stats',
    'StatStorage',
    'SimpleStatStore',
    'StatBackend',
]

#** Classes **#

class Stats(Serde):
    """
    Statistics Measurement
    """
    hour:            int
    total_queries:   int = 0
    blocked_queries: int = 0
    with_authority:  int = 0
    query_counts:    Dict[RType, int] = field(default_factory=dict)
    query_sources:   Dict[str, int]   = field(default_factory=dict)

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
    def count_authority(self):
        """
        update count for an authoritative answer
        """
        raise NotImplementedError

    @abstractmethod
    def count_question(self, rtype: RType):
        """
        update count for number of questions serviced
        """
        raise NotImplementedError

    @abstractmethod
    def count_block(self, rtype: RType):
        """
        update count for number of questions blocked
        """
        raise NotImplementedError

    @abstractmethod
    def count_source(self, source: str):
        """
        update count for answers of specific sources
        """
        raise NotImplementedError

class SimpleStatStore(StatStorage):
    """
    simple dictionary based stats storage (supports in-memory dict or dbm)
    """
    __slots__ = ('data', )

    def __init__(self, store: MutableMapping[bytes, bytes] = {}):
        self.data = store

    @classmethod
    def with_dbm(cls, fpath: Optional[str] = None) -> 'SimpleStatStore':
        """
        spawn simple stat store with dbm store
        """
        store = dbm.open(fpath or 'stats.db', 'c')
        return cls(cast(MutableMapping, store))

    def stats(self) -> List[Stats]:
        """
        compile statistics for each hour in the data from store
        """
        stats: Dict[int, Stats] = {}
        for key in self.data.keys():
            (value, )   = struct.unpack('>Q', self.data[key])
            hour, *rest = key.decode().split('_', 2)
            key,  end   = rest if len(rest) > 1 else (rest[0], None)
            hour        = int(hour)
            if hour not in stats:
                stats[hour] = Stats(hour)
            if key == 'authority':
                stats[hour].with_authority = value
            elif key == 'questions':
                if end is None:
                    stats[hour].total_queries = value
                else:
                    rtype = RType[end]
                    stats[hour].query_counts[rtype] = value
            elif key == 'blocked':
                stats[hour].blocked_queries = value
            elif key == 'source' and end is not None:
                stats[hour].query_sources[end] = value
        statistics = list(stats.values())
        statistics.sort(key=lambda s: s.hour)
        return statistics

    def _update(self, key: bytes, count: int):
        key   = f'{datetime.now().hour}_'.encode() + key
        value = self.data.get(key, None)
        if value is not None:
            (prev, ) = struct.unpack('>Q', value)
            count   += prev
        self.data[key] = struct.pack('>Q', count)

    def count_authority(self):
        self._update(b'authority', 1)

    def count_question(self, rtype: RType):
        self._update(b'questions', 1)
        self._update(f'questions_{rtype.name}'.encode(), 1)

    def count_block(self, rtype: RType):
        self._update(f'blocked_{rtype.name}'.encode(), 1)

    def count_source(self, source: str):
        self._update(f'source_{source}'.encode(), 1)

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
