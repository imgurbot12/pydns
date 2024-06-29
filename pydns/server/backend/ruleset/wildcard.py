"""
WildCard Matching Implementation
"""
from typing import Optional, List
from typing_extensions import Self

from pyderive import dataclass, field

#** Variables **#
__all__ = ['WildcardMatch']

#** Classes **#

@dataclass(slots=True)
class WildcardMatch:
    """
    Match a String against a Wildcarded Pattern
    """
    prefix: Optional[bytes] = None
    middle: List[bytes]     = field(default_factory=list)
    suffix: Optional[bytes] = None

    @classmethod
    def compile(cls, pattern: str) -> Self:
        """
        Compile the specified pattern into a matcher object

        :param pattern: wildcard pattern to match
        :return:        compiled pattern matcher
        """
        chunks = [c for c in pattern.encode().split(b'*')]
        prefix = chunks.pop(0)
        suffix = chunks.pop() if chunks else None
        return cls(prefix or None, chunks, suffix or None)

    def match(self, string: bytes) -> bool:
        """
        determine if specified string matches the compiled pattern

        :param string: string to compare to pattern
        :return:       true if pattern matches compiled expression
        """
        if self.prefix and not string.startswith(self.prefix):
            return False
        index = 0
        for middle in self.middle:
            sidx = string.find(middle, index)
            if sidx < 0:
                return False
            index = sidx + 1
        if self.suffix and not string.endswith(self.suffix, index):
            return False
        return True
