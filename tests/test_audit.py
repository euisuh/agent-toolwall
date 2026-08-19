import json

import toolwall
from toolwall.audit import AuditLog
from toolwall.types import Decision, Effect


RECORD_KEYS = {
    "ts",
    "toolwall_version",
    "tool",
    "args",
    "context",
    "effect",
    "reason",
    "policy",
    "escalated",
    "approved",
    "error",
    "duration_ms",
}


def test_one_check_writes_one_record_and_ten_checks_write_ten_lines(tmp_path):
    memory = AuditLog()
    wall = toolwall.Toolwall([], default=Effect.DENY, audit=memory)
    wall.check("read_file", {})
    assert len(memory.records) == 1

    path = tmp_path / "audit.jsonl"
    wall = toolwall.Toolwall([], default=Effect.DENY, audit=AuditLog(path))
    for _ in range(10):
        wall.check("read_file", {})
    assert len(path.read_text().splitlines()) == 10


def test_allowed_calls_are_recorded():
    audit = AuditLog()
    toolwall.Toolwall([], default=Effect.ALLOW, audit=audit).check("read_file", {})
    assert any(record["effect"] == "allow" for record in audit.records)


def test_record_shape_and_types():
    audit = AuditLog()
    toolwall.Toolwall([], default=Effect.ALLOW, audit=audit).check(
        "read_file", {"path": "a"}, {"session_id": "s1"}
    )
    record = audit.records[0]
    assert set(record) == RECORD_KEYS
    assert isinstance(record["ts"], str)
    assert record["toolwall_version"] == toolwall.__version__
    assert isinstance(record["toolwall_version"], str)
    assert isinstance(record["tool"], str)
    assert isinstance(record["args"], dict)
    assert isinstance(record["context"], dict)
    assert record["effect"] in {"allow", "deny", "escalate"}
    assert isinstance(record["reason"], str)
    assert isinstance(record["policy"], str)
    assert record["escalated"] is False
    assert record["approved"] is None
    assert record["error"] is None
    assert isinstance(record["duration_ms"], float)


def test_redacts_normalized_keys_at_any_depth():
    audit = AuditLog(redact=["api_key"])
    toolwall.Toolwall([], default=Effect.ALLOW, audit=audit).check(
        "request",
        {"api_key": "sk-real", "nested": {"API_KEY": "sk-real"}},
    )
    assert "sk-real" not in json.dumps(audit.records[0])


def test_file_is_flushed_after_each_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    toolwall.Toolwall([], default=Effect.ALLOW, audit=audit).check("read_file", {})
    with path.open(encoding="utf-8") as reader:
        assert len(reader.readlines()) == 1


def test_non_json_serializable_argument_is_coerced(tmp_path):
    class Custom:
        pass

    path = tmp_path / "audit.jsonl"
    toolwall.Toolwall([], default=Effect.ALLOW, audit=AuditLog(path)).check(
        "custom", {"value": Custom()}
    )
    record = json.loads(path.read_text())
    assert isinstance(record["args"]["value"], str)
    assert "Custom object" in record["args"]["value"]


def test_policy_exception_is_denied_and_recorded():
    def broken_policy(call):
        raise ValueError("broken")

    audit = AuditLog()
    decision = toolwall.Toolwall(
        [broken_policy], default=Effect.ALLOW, audit=audit
    ).check("tool", {})
    assert decision.effect is Effect.DENY
    assert audit.records[0]["effect"] == "deny"
    assert "ValueError('broken')" in audit.records[0]["error"]


def test_record_is_written_when_escalation_resolves():
    def escalating_policy(call):
        return Decision(Effect.ESCALATE, "sensitive", "sensitive", call.args)

    audit = AuditLog()
    wall = toolwall.Toolwall([escalating_policy], default=Effect.DENY, audit=audit)
    assert wall.check("tool", {}).effect is Effect.DENY
    assert len(audit.records) == 1
    assert audit.records[0]["escalated"] is True
    assert audit.records[0]["approved"] is False
