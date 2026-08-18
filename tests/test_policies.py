import pytest

from toolwall import Effect, Toolwall
from toolwall.policies import arg_rules


def check(rules, args, tool="send_email"):
    return Toolwall([arg_rules(rules)], default=Effect.ALLOW).check(tool, args)


@pytest.mark.parametrize(
    ("constraint", "value"),
    [
        pytest.param({"required": True}, "x", id="required"),
        pytest.param({"type": "int"}, 1, id="type"),
        pytest.param({"max_len": 3}, "abc", id="max_len"),
        pytest.param({"enum": ["draft", "sent"]}, "draft", id="enum"),
        pytest.param({"matches": r"^ok$"}, "ok", id="matches"),
        pytest.param({"denies": r"SECRET"}, "public", id="denies"),
        pytest.param({"allow_hosts": ["example.com"]}, "ok@example.com", id="allow_hosts"),
    ],
)
def test_each_constraint_allows_valid_value(constraint, value) -> None:
    assert check({"send_email": {"to": constraint}}, {"to": value}).effect is Effect.ALLOW


@pytest.mark.parametrize(
    ("constraint", "args", "name"),
    [
        pytest.param({"required": True}, {}, "required", id="required"),
        pytest.param({"type": "int"}, {"to": True}, "type", id="type-bool-is-not-int"),
        pytest.param({"max_len": 3}, {"to": "abcd"}, "max_len", id="max_len"),
        pytest.param({"enum": ["draft"]}, {"to": "sent"}, "enum", id="enum"),
        pytest.param({"matches": r"^ok$"}, {"to": "no"}, "matches", id="matches"),
        pytest.param({"denies": r"SECRET"}, {"to": "a SECRET"}, "denies", id="denies"),
        pytest.param(
            {"allow_hosts": ["example.com"]},
            {"to": "bad@evil.example"},
            "allow_hosts",
            id="allow_hosts",
        ),
    ],
)
def test_each_constraint_denies_invalid_value(constraint, args, name) -> None:
    decision = check({"send_email": {"to": constraint}}, args)
    assert decision.effect is Effect.DENY
    assert name in decision.reason
    assert "value" in decision.reason
    assert decision.policy == "arg_rules:send_email.to"


def test_matches_denies_parent_path_traversal() -> None:
    decision = check(
        {"write_file": {"path": {"matches": r"^/workspace/"}}},
        {"path": "/workspace/../etc/passwd"},
        "write_file",
    )
    assert decision.effect is Effect.DENY
    assert "matches" in decision.reason


def test_allow_hosts_denies_url_userinfo_trick() -> None:
    decision = check(
        {"send_email": {"to": {"allow_hosts": ["example.com"]}}},
        {"to": "https://example.com@evil.example/x"},
    )
    assert decision.effect is Effect.DENY


def test_allow_hosts_accepts_casefolded_url_host() -> None:
    decision = check(
        {"send_email": {"to": {"allow_hosts": ["example.com"]}}},
        {"to": "https://EXAMPLE.COM/x"},
    )
    assert decision.effect is Effect.ALLOW


def test_allow_hosts_bare_entry_denies_subdomain() -> None:
    decision = check(
        {"send_email": {"to": {"allow_hosts": ["example.com"]}}},
        {"to": "https://sub.example.com"},
    )
    assert decision.effect is Effect.DENY


def test_allow_hosts_leading_dot_accepts_subdomain() -> None:
    decision = check(
        {"send_email": {"to": {"allow_hosts": [".example.com"]}}},
        {"to": "https://sub.example.com"},
    )
    assert decision.effect is Effect.ALLOW


def test_allow_hosts_denies_comma_smuggled_recipient() -> None:
    decision = check(
        {"send_email": {"to": {"type": "str", "allow_hosts": ["example.com"]}}},
        {"to": "ok@example.com, attacker@evil.example"},
    )
    assert decision.effect is Effect.DENY


@pytest.mark.parametrize("value", ["not a url", ""], ids=["words", "empty"])
def test_allow_hosts_denies_unparseable_or_hostless_value(value) -> None:
    decision = check(
        {"send_email": {"to": {"allow_hosts": ["example.com"]}}}, {"to": value}
    )
    assert decision.effect is Effect.DENY


def test_allow_hosts_denies_ip_unless_explicitly_allowlisted() -> None:
    value = "http://127.0.0.1:8080/x"
    denied = check(
        {"send_email": {"to": {"allow_hosts": ["example.com"]}}}, {"to": value}
    )
    allowed = check(
        {"send_email": {"to": {"allow_hosts": ["127.0.0.1"]}}}, {"to": value}
    )
    assert denied.effect is Effect.DENY
    assert allowed.effect is Effect.ALLOW


def test_global_wildcard_denies_canary_in_any_tool_argument() -> None:
    decision = check(
        {"*": {"*": {"denies": r"CANARY-[0-9A-F]{4}"}}},
        {"unknown": "prefix CANARY-7F3A suffix"},
        "unlisted_tool",
    )
    assert decision.effect is Effect.DENY
    assert decision.policy == "arg_rules:unlisted_tool.unknown"


def test_on_violation_redact_replaces_match_and_allows() -> None:
    decision = check(
        {"send_email": {"body": {"denies": r"SECRET-\d+", "on_violation": "redact"}}},
        {"body": "token SECRET-1234 here"},
    )
    assert decision.effect is Effect.ALLOW
    assert decision.args["body"] == "token [REDACTED] here"
    assert "redact" in decision.reason


def test_global_rule_denies_before_tool_specific_redaction() -> None:
    decision = check(
        {
            "*": {"*": {"denies": "BLOCK"}},
            "send_email": {
                "body": {"denies": "BLOCK", "on_violation": "redact"}
            },
        },
        {"body": "BLOCK"},
    )
    assert decision.effect is Effect.DENY
    assert decision.args["body"] == "BLOCK"


def test_global_redaction_does_not_skip_tool_specific_deny() -> None:
    decision = check(
        {
            "*": {"*": {"denies": "SECRET", "on_violation": "redact"}},
            "send_email": {"to": {"allow_hosts": ["example.com"]}},
        },
        {"to": "attacker@evil.example", "body": "SECRET"},
    )
    assert decision.effect is Effect.DENY
    assert decision.policy == "arg_rules:send_email.to"
    assert decision.args["body"] == "[REDACTED]"


def test_allow_hosts_list_denies_non_string_member() -> None:
    decision = check(
        {
            "send_email": {
                "to": {"type": "list", "allow_hosts": ["example.com"]}
            }
        },
        {"to": ["ok@example.com", 1]},
    )
    assert decision.effect is Effect.DENY


def test_argument_wildcard_runs_before_specific_argument_rule() -> None:
    decision = check(
        {
            "send_email": {
                "body": {"denies": "BLOCK", "on_violation": "redact"},
                "*": {"denies": "BLOCK"},
            }
        },
        {"body": "BLOCK"},
    )
    assert decision.effect is Effect.DENY
    assert decision.args["body"] == "BLOCK"
