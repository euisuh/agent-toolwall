from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]
    context: dict[str, Any]
    norm_tool: str = field(init=False)
    norm_args: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "norm_tool", self.tool)
        object.__setattr__(self, "norm_args", self.args)


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    policy: str
    args: dict[str, Any]


Policy: TypeAlias = Callable[[ToolCall], Decision | None]


class ToolCallBlocked(Exception):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


class PolicyError(Exception):
    pass
