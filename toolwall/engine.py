from collections.abc import Callable, Iterable
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from threading import Lock
from typing import Any

from .types import (
    Decision,
    Effect,
    NormalizationError,
    Policy,
    ToolCall,
    ToolCallBlocked,
)


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
        self._commit_lock = (
            Lock()
            if any(hasattr(policy, "commit") for policy in self.policies)
            else nullcontext()
        )

    def check(
        self,
        tool: str,
        args: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Decision:
        with self._commit_lock:
            return self._check(tool, args, context)

    def _check(
        self,
        tool: str,
        args: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> Decision:
        copied_args = deepcopy(args)
        try:
            call = ToolCall(tool, copied_args, dict(context or {}))
        except NormalizationError as exc:
            return Decision(Effect.DENY, str(exc), "normalization", copied_args)
        decided: Decision | None = None
        escalation: Decision | None = None

        for policy in self.policies:
            try:
                result = policy(call)
                if result is None:
                    continue
                call = replace(call, args=result.args)
                if result.effect is Effect.DENY:
                    decided = result
                    break
                if result.effect is Effect.ESCALATE:
                    escalation = result
                else:
                    decided = result
            except Exception as exc:
                decided = Decision(
                    Effect.DENY,
                    f"policy_error: {exc!r}",
                    "policy_error",
                    call.args,
                )
                break

        if decided is not None and decided.effect is Effect.DENY:
            return decided
        if escalation is not None:
            raise NotImplementedError("escalation is not implemented in M1")
        decision = decided or Decision(self.default, "default", "default", call.args)
        if decision.effect is Effect.ALLOW:
            try:
                for policy in self.policies:
                    commit = getattr(policy, "commit", None)
                    if commit is not None:
                        commit(call)
            except Exception as exc:
                return Decision(
                    Effect.DENY,
                    f"policy_error: {exc!r}",
                    "policy_error",
                    call.args,
                )
        return decision

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
