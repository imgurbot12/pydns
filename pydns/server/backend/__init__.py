"""
DNS Server Data Backend Implementations
"""
from abc import abstractmethod
from typing import NamedTuple, Optional, Protocol, List, ClassVar

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
]

#** Classes **#

class Answers(NamedTuple):
    """
    Backend DNS Answers Return Type
    """
    answers: List[Answer]
    source:  str
    rcode:   Optional[RCode] = None

class Backend(Protocol):
    """
    BaseClass Interface Definition for Backend Implementations
    """
    source: ClassVar[str]
    recursion_available: bool = False

    @abstractmethod
    def is_authority(self, domain: bytes) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_answers(self, domain: bytes, rtype: RType) -> Answers:
        raise NotImplementedError

#** Imports **#
from .cache import Cache
from .forwarder import Forwarder
from .memory import MemoryBackend
from .ruleset import BlockMode, RuleEngine, RuleBackend, DbmRuleEngine
