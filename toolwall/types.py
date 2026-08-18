from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias
import unicodedata


MAX_VALUE_DEPTH = 20
MAX_SCANNED_STRINGS = 10_000


class NormalizationError(ValueError):
    pass


def normalize_name(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def normalize_arg_key(value: str) -> str:
    return normalize_name(value)


def match_arg_key(value: str) -> str:
    # NFKC does not fold Cyrillic о; §8 requires it to match Latin o.
    return normalize_arg_key(value).translate({ord("о"): "o"})


def _normalize_value(value: Any, depth: int, scanned: list[int]) -> Any:
    if depth > MAX_VALUE_DEPTH:
        raise NormalizationError(f"argument value depth exceeds {MAX_VALUE_DEPTH}")
    if isinstance(value, str):
        scanned[0] += 1
        if scanned[0] > MAX_SCANNED_STRINGS:
            raise NormalizationError(
                f"argument value string count exceeds {MAX_SCANNED_STRINGS}"
            )
        return unicodedata.normalize("NFKC", value)
    if isinstance(value, list):
        return [_normalize_value(item, depth + 1, scanned) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_value(item, depth + 1, scanned)
            for key, item in value.items()
        }
    return value


def normalize_args(args: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    raw_keys: dict[str, str] = {}
    match_keys: dict[str, str] = {}
    scanned = [0]
    for raw_key, value in args.items():
        if not isinstance(raw_key, str):
            raise NormalizationError(f"argument key must be str: {raw_key!r}")
        key = normalize_arg_key(raw_key)
        if key in raw_keys and raw_keys[key] != raw_key:
            raise NormalizationError(
                f"ambiguous argument keys: {raw_keys[key]!r}, {raw_key!r}"
            )
        match_key = match_arg_key(key)
        if match_key in match_keys and match_keys[match_key] != raw_key:
            raise NormalizationError(
                f"ambiguous argument keys: {match_keys[match_key]!r}, {raw_key!r}"
            )
        raw_keys[key] = raw_key
        match_keys[match_key] = raw_key
        normalized[key] = _normalize_value(value, 0, scanned)
    return normalized


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
        object.__setattr__(self, "norm_tool", normalize_name(self.tool))
        object.__setattr__(self, "norm_args", normalize_args(self.args))


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
