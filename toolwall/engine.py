from collections.abc import Callable, Iterable
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from threading import Lock
from time import perf_counter
from typing import Any

from .audit import AuditLog
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

    def __init__(
        self,
        policies: Iterable[Policy],
        *,
        default: Effect,
        audit: AuditLog | None = None,
    ) -> None:
        if default is not Effect.ALLOW and default is not Effect.DENY:
            raise ValueError("default must be Effect.ALLOW or Effect.DENY")
        self.policies = tuple(policies)
        self.default = default
        self.audit = audit
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
        started = perf_counter()
        copied_args = deepcopy(args)
        incoming_args = deepcopy(copied_args)
        copied_context = dict(context or {})
        decision: Decision | None = None
        error: str | None = None
        try:
            try:
                call = ToolCall(tool, copied_args, copied_context)
            except NormalizationError as exc:
                decision = Decision(
                    Effect.DENY, str(exc), "normalization", copied_args
                )
                return decision
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
                    error = repr(exc)
                    decided = Decision(
                        Effect.DENY,
                        f"policy_error: {error}",
                        "policy_error",
                        call.args,
                    )
                    break

            if decided is not None and decided.effect is Effect.DENY:
                decision = decided
                return decision
            if escalation is not None:
                decision = escalation
                raise NotImplementedError("escalation is not implemented in M1")
            decision = decided or Decision(
                self.default, "default", "default", call.args
            )
            if decision.effect is not Effect.ALLOW:
                return decision
            try:
                for policy in self.policies:
                    commit = getattr(policy, "commit", None)
                    if commit is not None:
                        commit(call)
            except Exception as exc:
                error = repr(exc)
                decision = Decision(
                    Effect.DENY,
                    f"policy_error: {error}",
                    "policy_error",
                    call.args,
                )
            return decision
        finally:
            if self.audit is not None and decision is not None:
                from . import __version__

                self.audit.write(
                    {
                        "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace(
                            "+00:00", "Z"
                        ),
                        "toolwall_version": __version__,
                        "tool": tool,
                        "args": incoming_args,
                        "context": copied_context,
                        "effect": decision.effect.value,
                        "reason": decision.reason,
                        "policy": decision.policy,
                        "escalated": False,
                        "approved": None,
                        "error": error,
                        "duration_ms": (perf_counter() - started) * 1000,
                    }
                )

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
