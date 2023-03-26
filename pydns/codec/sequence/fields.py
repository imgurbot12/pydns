"""
Sequence Field Implementation
"""
from dataclasses import InitVar, dataclass
from typing import ClassVar, Union, Type, get_origin
from typing_extensions import Self

from .. import Codec, Int32

#** Variables **#

#** Functions **#

def cname(seq: Union[object, type]) -> str:
    if isinstance(seq, type):
        return seq.__name__
    return seq.__class__.__name__

def is_datavar(anno: type) -> bool:
    origin = get_origin(anno)
    return origin in (ClassVar, InitVar)

def compile_annotation(name: str, anno: type, level: int = 1):
    """

    """
    # skip processing if already a codec or supported type
    if isinstance(anno, Codec):
        return anno
    # convert common types to defaults
    if anno == int:
        return Int32
    # convert property
    if isinstance(anno, Property):
        anno.hint = compile_annotation(name, anno.hint, level+1)
        return anno
    # raise error on unsupported type
    raise ValueError(f'invalid annotatation: {name!r}: {anno}')

#** Classes **#

@dataclass
class Property:
    hint: type

    def __class_getitem__(cls, hint: type) -> Self:
        return cls(hint)

@dataclass
class Field:
    name:     str
    type:     Type[Codec]
    dataattr: bool = True
