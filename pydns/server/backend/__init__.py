"""
DNS Server Data Backend Implementations
"""
from abc import abstractmethod
from typing import Optional, Protocol, List, ClassVar
from typing_extensions import runtime_checkable

from pyderive import dataclass

from ... import Answer, RCode, RType

#** Variables **#
__all__ = [
    'Answers',
    'Backend',

    'Cache',
    'Forwarder',
    'MemoryBackend',

    'BlockMode',
    'RuleEngine',
    'RuleBackend',
    'DbmRuleEngine',

    'Stats',
    'StatStorage',
    'SimpleStatStore',
    'StatBackend',
]

#** Classes **#

@dataclass(slots=True)
class Answers:
    """
    Backend DNS Answers Return Type
    """
    answers:   List[Answer]
    source:    str
    rcode:     Optional[RCode] = None
    forwarder: Optional[str]   = None

@runtime_checkable
class Backend(Protocol):
    """
    BaseClass Interface Definition for Backend Implementations
    """
    source: ClassVar[str]
    recursion_available: bool = False

    @abstractmethod
    def is_authority(self, domain: bytes) -> bool:
        """
        determine if this backend is an authority on a given domain
        """
        raise NotImplementedError

    @abstractmethod
    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        """
        retrieve answers associated with the given domain and record type

        :param domain: domain being requested
        :param rtype:  record type being requested
        """
        raise NotImplementedError

    def count_blocked(self) -> int:
        """
        optional backend function to count unique blocked entries
        """
        backend = getattr(self, 'backend', None)
        if backend is not None and isinstance(backend, Backend):
            return backend.count_blocked()
        return 0

#** Imports **#
from .cache import Cache
from .forwarder import Forwarder
from .memory import MemoryBackend
from .ruleset import BlockMode, RuleEngine, RuleBackend, DbmRuleEngine
from .stats import Stats, StatStorage, SimpleStatStore, StatBackend
