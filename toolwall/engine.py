from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import replace
from typing import Any

from .types import Decision, Effect, Policy, ToolCall, ToolCallBlocked


class Toolwall:
    """Evaluate policies in order and fail closed on policy errors.

    Args are copied before evaluation. Decisions thread replacement args to later
    policies, the first DENY stops evaluation, and an unmatched call uses the
    caller-supplied default posture.
    """

    def __init__(self, policies: Iterable[Policy], *, default: Effect) -> None:
        if default is not Effect.ALLOW and default is not Effect.DENY:
            raise ValueError("default must be Effect.ALLOW or Effect.DENY")
        self.policies = tuple(policies)
        self.default = default

    def check(
        self,
        tool: str,
        args: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Decision:
        copied_args = deepcopy(args)
        call = ToolCall(tool, copied_args, dict(context or {}))
        decided: Decision | None = None
        escalation: Decision | None = None

        for policy in self.policies:
            try:
                result = policy(call)
                if result is None:
                    continue
                call = replace(call, args=result.args)
                if result.effect is Effect.DENY:
                    return result
                if result.effect is Effect.ESCALATE:
                    escalation = result
                else:
                    decided = result
            except Exception as exc:
                return Decision(
                    Effect.DENY,
                    f"policy_error: {exc!r}",
                    "policy_error",
                    call.args,
                )

        if escalation is not None:
            raise NotImplementedError("escalation is not implemented in M1")
        if decided is not None:
            return decided
        return Decision(self.default, "default", "default", call.args)

    def call(
        self,
        tool: str,
        args: dict[str, Any],
        fn: Callable[..., Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        decision = self.check(tool, args, context)
        if decision.effect is not Effect.ALLOW:
            raise ToolCallBlocked(decision)
        return fn(**decision.args)
