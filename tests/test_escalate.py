from io import StringIO

import pytest

from toolwall.audit import AuditLog
from toolwall.engine import Toolwall, cli_confirm
from toolwall.policies import arg_rules, sensitive
from toolwall.types import Effect, ToolCall


def test_sensitive_returns_escalate_without_matching_other_tools() -> None:
    policy = sensitive(["SUBMIT_ORDER"])

    assert policy(ToolCall("submit_order", {}, {})).effect is Effect.ESCALATE
    assert policy(ToolCall("read_file", {}, {})) is None


def test_default_auto_deny_records_escalation() -> None:
    audit = AuditLog()
    decision = Toolwall(
        [sensitive(["submit_order"])], default=Effect.ALLOW, audit=audit
    ).check("submit_order", {"sku": "X"})

    assert decision.effect is Effect.DENY
    assert audit.records[0]["escalated"] is True
    assert audit.records[0]["approved"] is False


def test_literal_true_approves_and_records_escalation() -> None:
    audit = AuditLog()
    decision = Toolwall(
        [sensitive(["submit_order"])],
        default=Effect.DENY,
        audit=audit,
        escalate=lambda call, decision: True,
    ).check("submit_order", {})

    assert decision.effect is Effect.ALLOW
    assert audit.records[0]["escalated"] is True
    assert audit.records[0]["approved"] is True


@pytest.mark.parametrize("result", ["yes", 1, None, False])
def test_non_literal_true_denies(result) -> None:
    audit = AuditLog()
    decision = Toolwall(
        [sensitive(["submit_order"])],
        default=Effect.ALLOW,
        audit=audit,
        escalate=lambda call, decision: result,
    ).check("submit_order", {})

    assert decision.effect is Effect.DENY
    assert audit.records[0]["approved"] is False


def test_callback_exception_denies_and_is_audited() -> None:
    def fail(call, decision):
        raise RuntimeError("approval unavailable")

    audit = AuditLog()
    decision = Toolwall(
        [sensitive(["submit_order"])],
        default=Effect.ALLOW,
        audit=audit,
        escalate=fail,
    ).check("submit_order", {})

    assert decision.effect is Effect.DENY
    assert audit.records[0]["approved"] is False
    assert "RuntimeError('approval unavailable')" in audit.records[0]["error"]


@pytest.mark.parametrize("sensitive_first", [False, True])
def test_arg_deny_never_invokes_callback_in_either_order(sensitive_first) -> None:
    invocations = []
    audit = AuditLog()
    deny = arg_rules({"send_email": {"to": {"required": True}}})
    escalate = sensitive(["send_email"])
    policies = [escalate, deny] if sensitive_first else [deny, escalate]
    decision = Toolwall(
        policies,
        default=Effect.ALLOW,
        audit=audit,
        escalate=lambda call, decision: invocations.append(call) or True,
    ).check("send_email", {})

    assert decision.effect is Effect.DENY
    assert invocations == []
    assert audit.records[0]["escalated"] is sensitive_first
    assert audit.records[0]["approved"] is None


def test_cli_confirm_non_tty_does_not_read(monkeypatch) -> None:
    class NonTty:
        def isatty(self):
            return False

        def readline(self):
            raise AssertionError("stdin was read")

    monkeypatch.setattr("sys.stdin", NonTty())
    assert cli_confirm(None, None) is False


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        ("y\n", True),
        ("yes\n", True),
        ("n\n", False),
        ("", False),
        ("Y E S", False),
    ],
)
def test_cli_confirm_tty_accepts_only_y_or_yes(
    monkeypatch, capsys, input_value, expected
) -> None:
    class Tty(StringIO):
        def isatty(self):
            return True

    class Call:
        tool = "submit_order"
        args = {"sku": "X", "amount": 499}

    class Decision:
        reason = "sensitive action"

    monkeypatch.setattr("sys.stdin", Tty(input_value))
    assert cli_confirm(Call(), Decision()) is expected
    output = capsys.readouterr().out
    assert "submit_order" in output
    assert "'amount': 499" in output
    assert "sensitive action" in output
