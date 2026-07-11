from contextlib import AbstractContextManager
from re import Pattern
from typing import Any, Sequence

def raises(
    expected_exception: type[BaseException] | tuple[type[BaseException], ...],
    *,
    match: str | Pattern[str] | None = ...,
) -> AbstractContextManager[Any]: ...

def main(args: Sequence[str] | None = ...) -> int: ...
