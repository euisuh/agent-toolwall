from collections.abc import Iterable

from .types import Decision, Effect, Policy, ToolCall


def tool_allowlist(names: Iterable[str]) -> Policy:
    allowed = frozenset(names)

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
    denied = frozenset(names)

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
