import pytest

from toolwall import Effect, ToolCallBlocked, Toolwall
from toolwall.policies import tool_allowlist, tool_denylist


def test_allowlist_with_default_deny() -> None:
    wall = Toolwall([tool_allowlist(["read_file"])], default=Effect.DENY)

    assert wall.check("read_file", {"path": "a"}).effect is Effect.ALLOW
    denied = wall.check("send_email", {})
    assert denied.effect is Effect.DENY
    assert denied.reason == "default"


def test_denylist_with_default_allow() -> None:
    wall = Toolwall([tool_denylist(["send_email"])], default=Effect.ALLOW)

    assert wall.check("read_file", {"path": "a"}).effect is Effect.ALLOW
    assert wall.check("send_email", {}).effect is Effect.DENY


def test_empty_default_deny_wall_denies_every_call() -> None:
    wall = Toolwall([], default=Effect.DENY)

    assert wall.check("read_file", {}).effect is Effect.DENY
    assert wall.check("send_email", {}).effect is Effect.DENY


def test_policy_exception_fails_closed() -> None:
    def broken_policy(call):
        raise ValueError("broken")

    decision = Toolwall([broken_policy], default=Effect.ALLOW).check("tool", {})

    assert decision.effect is Effect.DENY
    assert decision.reason.startswith("policy_error:")


def test_check_copies_args_without_mutating_input() -> None:
    args = {"nested": {"value": 1}}
    decision = Toolwall([], default=Effect.ALLOW).check("tool", args)

    assert args == {"nested": {"value": 1}}
    assert decision.args is not args
    assert decision.args["nested"] is not args["nested"]


def test_call_executes_allowed_function() -> None:
    wall = Toolwall([], default=Effect.ALLOW)

    assert wall.call("add", {"left": 2, "right": 3}, lambda left, right: left + right) == 5


def test_call_blocks_function_execution() -> None:
    called = False

    def fn() -> None:
        nonlocal called
        called = True

    with pytest.raises(ToolCallBlocked) as caught:
        Toolwall([], default=Effect.DENY).call("blocked", {}, fn)

    assert caught.value.decision.effect is Effect.DENY
    assert called is False


def test_wildcard_lists_match_every_tool() -> None:
    assert Toolwall([tool_allowlist(["*"])], default=Effect.DENY).check("any", {}).effect is Effect.ALLOW
    assert Toolwall([tool_denylist(["*"])], default=Effect.ALLOW).check("any", {}).effect is Effect.DENY
