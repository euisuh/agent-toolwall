from collections import deque
from collections.abc import Callable, Iterable, Sequence
from copy import deepcopy
import re
from threading import Lock
import time
from typing import Any
import unicodedata
from urllib.parse import urlsplit

from .types import Decision, Effect, Policy, ToolCall, match_arg_key, normalize_name


def tool_allowlist(names: Iterable[str]) -> Policy:
    allowed = frozenset(normalize_name(name) if name != "*" else name for name in names)

    def policy(call: ToolCall) -> Decision | None:
        if "*" in allowed or call.norm_tool in allowed:
            return Decision(
                Effect.ALLOW,
                f"tool {call.tool!r} is allowlisted",
                "tool_allowlist",
                call.args,
            )
        return None

    return policy


def tool_denylist(names: Iterable[str]) -> Policy:
    denied = frozenset(normalize_name(name) if name != "*" else name for name in names)

    def policy(call: ToolCall) -> Decision | None:
        if "*" in denied or call.norm_tool in denied:
            return Decision(
                Effect.DENY,
                f"tool {call.tool!r} is denylisted",
                "tool_denylist",
                call.args,
            )
        return None

    return policy


def sensitive(tools: Iterable[str]) -> Policy:
    sensitive_tools = frozenset(
        normalize_name(tool) if tool != "*" else tool for tool in tools
    )

    def policy(call: ToolCall) -> Decision | None:
        if "*" in sensitive_tools or call.norm_tool in sensitive_tools:
            return Decision(
                Effect.ESCALATE,
                f"tool {call.tool!r} requires approval",
                f"sensitive:{call.norm_tool}",
                call.args,
            )
        return None

    return policy


def rate_limit(
    tool: str,
    max_calls: int,
    per_seconds: float,
    key: Sequence[str] = (),
    clock: Callable[[], float] = time.monotonic,
) -> Policy:
    """Limit allowed calls per sliding window, optionally keyed by context."""
    norm_tool = normalize_name(tool)
    windows: dict[tuple[Any, ...], deque[float]] = {}
    lock = Lock()

    def window_key(call: ToolCall) -> tuple[Any, ...]:
        return (call.norm_tool, *(call.context.get(name) for name in key))

    def evict(timestamps: deque[float], now: float) -> None:
        while timestamps and now - timestamps[0] > per_seconds:
            timestamps.popleft()

    def policy(call: ToolCall) -> Decision | None:
        if call.norm_tool != norm_tool:
            return None
        with lock:
            timestamps = windows.setdefault(window_key(call), deque())
            evict(timestamps, clock())
            if len(timestamps) >= max_calls:
                return Decision(
                    Effect.DENY,
                    f"rate limit {max_calls} calls per {per_seconds} seconds exceeded",
                    f"rate_limit:{norm_tool}",
                    call.args,
                )
        return None

    def commit(call: ToolCall) -> None:
        if call.norm_tool != norm_tool:
            return
        with lock:
            now = clock()
            timestamps = windows.setdefault(window_key(call), deque())
            evict(timestamps, now)
            timestamps.append(now)

    # ponytail: in-process; per-key deque is fine to ~10^4 keys.
    policy.commit = commit  # type: ignore[attr-defined]
    return policy


_TYPES = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list": list,
    "dict": dict,
}


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)


def _redact(value: Any, pattern: re.Pattern[str]) -> Any:
    if isinstance(value, str):
        return pattern.sub("[REDACTED]", unicodedata.normalize("NFKC", value))
    if isinstance(value, list):
        return [_redact(item, pattern) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item, pattern) for key, item in value.items()}
    return value


def _host(value: str) -> str | None:
    try:
        if "://" in value:
            host = urlsplit(value).hostname
        elif value.count("@") == 1:
            host = value.rsplit("@", 1)[1]
        else:
            host = value
        if not host or any(char.isspace() for char in host):
            return None
        return host.casefold().encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _host_allowed(host: str, entries: tuple[str, ...]) -> bool:
    for entry in entries:
        suffix = entry.startswith(".")
        candidate = _host(entry[1:] if suffix else entry)
        if candidate and (host.endswith(f".{candidate}") if suffix else host == candidate):
            return True
    return False


def arg_rules(rules: dict) -> Policy:
    """Validate normalized args; global rules run before tool-specific rules."""
    prepared: dict[str, dict[str, dict[str, Any]]] = {}
    for raw_tool, arg_map in rules.items():
        tool = raw_tool if raw_tool == "*" else normalize_name(raw_tool)
        prepared[tool] = {}
        for raw_arg, constraint in arg_map.items():
            arg = raw_arg if raw_arg == "*" else match_arg_key(raw_arg)
            item = dict(constraint)
            if "matches" in item:
                item["matches"] = re.compile(item["matches"])
            if "denies" in item:
                item["denies"] = re.compile(item["denies"])
            if "allow_hosts" in item:
                item["allow_hosts"] = tuple(item["allow_hosts"])
            prepared[tool][arg] = item

    def violation(call: ToolCall, arg: str, name: str, value: Any) -> Decision:
        return Decision(
            Effect.DENY,
            f"{name} violation for value {value!r}",
            f"arg_rules:{call.norm_tool}.{arg}",
            call.args,
        )

    def check_constraint(
        call: ToolCall,
        arg: str,
        raw_arg: str,
        value: Any,
        constraint: dict[str, Any],
    ) -> Decision | None:
        if constraint.get("required") and value is None:
            return violation(call, arg, "required", value)
        if value is None:
            return None
        type_name = constraint.get("type")
        if type_name:
            expected = _TYPES[type_name]
            valid = type(value) is expected
            if not valid:
                return violation(call, arg, "type", value)
        if "max_len" in constraint:
            try:
                too_long = len(value) > constraint["max_len"]
            except TypeError:
                too_long = True
            if too_long:
                return violation(call, arg, "max_len", value)
        if "enum" in constraint and value not in constraint["enum"]:
            return violation(call, arg, "enum", value)
        if "matches" in constraint:
            strings = tuple(_strings(value))
            if any(".." in item for item in strings) or not strings or any(
                constraint["matches"].search(item) is None for item in strings
            ):
                return violation(call, arg, "matches", value)
        if "denies" in constraint:
            pattern = constraint["denies"]
            if any(pattern.search(item) for item in _strings(value)):
                if constraint.get("on_violation", "deny") == "redact":
                    args = deepcopy(call.args)
                    args[raw_arg] = _redact(args[raw_arg], pattern)
                    redaction = Decision(
                        Effect.ALLOW,
                        f"denies violation redacted value {value!r}",
                        f"arg_rules:{call.norm_tool}.{arg}",
                        args,
                    )
                    value = _redact(value, pattern)
                else:
                    return violation(call, arg, "denies", value)
            else:
                redaction = None
        else:
            redaction = None
        if "allow_hosts" in constraint:
            values = value if type_name == "list" else [value]
            if not values or any(not isinstance(item, str) for item in values):
                return violation(call, arg, "allow_hosts", value)
            for item in values:
                if type_name != "list" and (
                    "," in item or any(char.isspace() for char in item)
                ):
                    return violation(call, arg, "allow_hosts", item)
                host = _host(item)
                if host is None or not _host_allowed(host, constraint["allow_hosts"]):
                    return violation(call, arg, "allow_hosts", item)
        return redaction

    def policy(call: ToolCall) -> Decision | None:
        raw_by_norm = {match_arg_key(key): key for key in call.args}
        values_by_norm = {match_arg_key(key): value for key, value in call.norm_args.items()}
        redaction = None
        tools = ("*",) if call.norm_tool == "*" else ("*", call.norm_tool)
        for tool in tools:
            tool_rules = prepared.get(tool, {})
            ordered_args = (["*"] if "*" in tool_rules else []) + [
                arg for arg in tool_rules if arg != "*"
            ]
            for arg in ordered_args:
                constraint = tool_rules[arg]
                if arg == "*":
                    targets = tuple(values_by_norm.items())
                else:
                    targets = ((arg, values_by_norm.get(arg)),)
                for target, value in targets:
                    raw_arg = raw_by_norm.get(target, target)
                    result = check_constraint(call, target, raw_arg, value, constraint)
                    if result is not None and result.effect is Effect.DENY:
                        return result
                    if result is not None:
                        redaction = result
                        call = ToolCall(call.tool, result.args, call.context)
                        values_by_norm = {
                            match_arg_key(key): value
                            for key, value in call.norm_args.items()
                        }
        return redaction

    return policy
