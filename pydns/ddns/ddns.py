from typing import Optional

from .content import ANY
from ..const import Type, Class
from ..questions import Question
from ..records import ResourceRecord, RecordContent

# money patch content-classes to use ANY
from ..records.records import _content_classes
_content_classes['ANY'] = ANY

#** Variables **#
__all__ = ['Zone', 'PreRequisite', 'Update']

#** Classes **#

class Zone(Question):
    """aliased question object designed for Zone designation in Dynamic DNS"""

class PreRequisite(ResourceRecord):
    """aliased record object designed for required RRsets in Dynamic DNS"""

    def __init__(self,
        name:    str,
        content: Optional[RecordContent] = None,
        rclass:  Class                   = Class.IN,
        ttl:     int                     = 0,
    ):
        """
        :param name:    name of domain the pre-requisite is linked to
        :param content: type of content or required records that must exist
        :param rclass:  class the required record(s) are related to
        :param ttl:     (always zero but left for compatability)
        """
        self.name    = name
        self.rclass  = rclass
        self.ttl     = 0
        self.content = content or ANY()

class Update(ResourceRecord):
    """aliased record object designed to update the given resources"""
