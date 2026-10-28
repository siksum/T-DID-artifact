"""History store. Rules read through a view and propose deltas; the engine commits deltas only after
every rule evaluated the event without error, so a failing record never leaves partial state."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Delta:
    namespace: str
    key: str
    value: Any


@dataclass
class State:
    data: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        value = self.data.get(namespace, {}).get(key, default)
        return copy.deepcopy(value)

    def commit(self, deltas: list[Delta]) -> None:
        for d in deltas:
            self.data.setdefault(d.namespace, {})[d.key] = copy.deepcopy(d.value)


@dataclass(frozen=True)
class View:
    """Read-only access for one rule evaluation."""

    state: State
    stream_complete: Callable[[str], bool]
    unit_complete: Callable[[str, str | None], bool] = lambda role, service: True

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        return self.state.get(namespace, key, default)
