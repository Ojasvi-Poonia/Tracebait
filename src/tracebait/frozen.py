"""A read-only mapping that, unlike MappingProxyType, can be hashed, pickled and copied."""

from collections.abc import Iterator, Mapping
from typing import Generic, TypeVar

_K = TypeVar("_K")
_V = TypeVar("_V")


class FrozenMap(Mapping[_K, _V], Generic[_K, _V]):
    __slots__ = ("_data",)
    _data: dict[_K, _V]

    def __init__(self, data: Mapping[_K, _V]) -> None:
        object.__setattr__(self, "_data", dict(data))

    def __getitem__(self, key: _K) -> _V:
        return self._data[key]

    def __iter__(self) -> Iterator[_K]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __hash__(self) -> int:
        return hash(frozenset(self._data.items()))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is read-only")

    def __reduce__(self) -> tuple[type["FrozenMap[_K, _V]"], tuple[dict[_K, _V]]]:
        return (type(self), (self._data,))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._data!r})"
