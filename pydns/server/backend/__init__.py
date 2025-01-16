"""
DNS Server Data Backend Implementations
"""
from abc import abstractmethod
from typing import NamedTuple, Protocol, List, ClassVar

from ... import RType, Answer

#** Variables **#
__all__ = [
    'Answers',
    'Backend',

    'Cache',
    'Forwarder',
    'MemoryBackend',

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
from .ruleset import RuleEngine, RuleBackend, DbmRuleEngine
