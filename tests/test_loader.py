import json
from pathlib import Path

import pytest
import yaml

from toolwall import Effect, PolicyError, Toolwall, load_policy_file
from toolwall.loader import main
from toolwall.policies import (
    arg_rules,
    rate_limit,
    sensitive,
    tool_allowlist,
    tool_denylist,
)


BASE = {"version": 1, "default": "deny", "tools": {}}


def write_yaml(tmp_path: Path, data, name: str = "policy.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def assert_rejected(tmp_path: Path, data, key_path: str) -> None:
    with pytest.raises(PolicyError) as caught:
        load_policy_file(write_yaml(tmp_path, data))
    assert key_path in str(caught.value)


def test_emitted_policy_order_matches_contract() -> None:
    policies, default, audit = load_policy_file("toolwall/demo_policy.yaml")
    assert [policy._toolwall_name for policy in policies] == [
        "arg_rules:*",
        "tool_allowlist:read_file,http_get,send_email,submit_order",
        "arg_rules:read_file,http_get,send_email",
        "rate_limit:http_get",
        "sensitive:send_email,submit_order",
    ]
    assert default is Effect.DENY
    assert audit is not None


def test_round_trip_matches_hand_constructed_engine() -> None:
    loaded = Toolwall.from_file("toolwall/demo_policy.yaml", escalate=lambda *_: True)
    hand = Toolwall(
        [
            arg_rules({"*": {"*": {"denies": "CANARY-[0-9A-F]{4}"}}}),
            tool_allowlist(["read_file", "http_get", "send_email", "submit_order"]),
            arg_rules(
                {
                    "read_file": {
                        "path": {
                            "type": "str",
                            "required": True,
                            "matches": "^/workspace/",
                        }
                    },
                    "http_get": {
                        "url": {
                            "type": "str",
                            "required": True,
                            "allow_hosts": [".example.com", "docs.python.org"],
                        }
                    },
                    "send_email": {
                        "to": {
                            "type": "str",
                            "required": True,
                            "allow_hosts": ["example.com"],
                        }
                    },
                }
            ),
            rate_limit("http_get", 5, 60, ["session_id"]),
            sensitive(["send_email", "submit_order"]),
        ],
        default=Effect.DENY,
        escalate=lambda *_: True,
    )
    cases = [
        ("read_file", {"path": "/workspace/a.txt"}),
        ("read_file", {"path": "/etc/passwd"}),
        ("read_file", {}),
        ("http_get", {"url": "https://docs.python.org/3/"}),
        ("http_get", {"url": "https://api.example.com/x"}),
        ("http_get", {"url": "https://evil.example/x"}),
        ("send_email", {"to": "person@example.com"}),
        ("send_email", {"to": "attacker@evil.example"}),
        ("submit_order", {"symbol": "AAPL"}),
        ("unknown", {"body": "CANARY-7F3A"}),
        ("unknown", {}),
    ]
    for tool, args in cases:
        left = loaded.check(tool, args, {"session_id": "s1"})
        right = hand.check(tool, args, {"session_id": "s1"})
        assert (left.effect, left.policy, left.args) == (
            right.effect,
            right.policy,
            right.args,
        )


def test_allow_false_emits_denylist(tmp_path: Path) -> None:
    path = write_yaml(
        tmp_path,
        {"version": 1, "default": "allow", "tools": {"shell": {"allow": False}}},
    )
    wall = Toolwall.from_file(path)
    assert wall.check("shell", {}).effect is Effect.DENY
    assert wall.check("other", {}).effect is Effect.ALLOW


def test_missing_version_rejected_with_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, {"default": "deny"}, "version")


def test_non_one_version_rejected_with_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, {"version": 2, "default": "deny"}, "version")


def test_missing_default_rejected_with_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, {"version": 1}, "default")


def test_invalid_default_rejected_with_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, {"version": 1, "default": "permit"}, "default")


def test_unknown_top_level_key_rejected_with_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, {**BASE, "defaults": "allow"}, "defaults")


def test_unknown_tool_key_typo_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"read_file": {"allw": True}}}
    assert_rejected(tmp_path, data, "tools.read_file.allw")


def test_validate_cli_prints_error_and_returns_one(tmp_path: Path, capsys) -> None:
    path = write_yaml(tmp_path, {"version": 1})
    assert main(["--validate", str(path)]) == 1
    assert "default" in capsys.readouterr().err


def test_unknown_arg_constraint_key_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"read_file": {"args": {"path": {"requird": True}}}}}
    assert_rejected(tmp_path, data, "tools.read_file.args.path.requird")


def test_invalid_matches_regex_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"read_file": {"args": {"path": {"matches": "["}}}}}
    assert_rejected(tmp_path, data, "tools.read_file.args.path.matches")


def test_invalid_denies_regex_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"read_file": {"args": {"path": {"denies": "("}}}}}
    assert_rejected(tmp_path, data, "tools.read_file.args.path.denies")


def test_non_positive_rate_limit_max_rejected_with_path(tmp_path: Path) -> None:
    data = {
        **BASE,
        "tools": {"http_get": {"rate_limit": {"max": 0, "per_seconds": 60}}},
    }
    assert_rejected(tmp_path, data, "tools.http_get.rate_limit.max")


def test_invalid_allow_hosts_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"http_get": {"args": {"url": {"allow_hosts": [""]}}}}}
    assert_rejected(tmp_path, data, "tools.http_get.args.url.allow_hosts")


def test_invalid_enum_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"order": {"args": {"side": {"enum": "buy"}}}}}
    assert_rejected(tmp_path, data, "tools.order.args.side.enum")


def test_unsupported_type_rejected_with_path(tmp_path: Path) -> None:
    data = {**BASE, "tools": {"order": {"args": {"qty": {"type": "number"}}}}}
    assert_rejected(tmp_path, data, "tools.order.args.qty.type")


def test_invalid_yaml_refuses_to_construct_toolwall(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("tools: [", encoding="utf-8")
    constructed = False
    original = Toolwall.__init__

    def spy(self, *args, **kwargs):
        nonlocal constructed
        constructed = True
        original(self, *args, **kwargs)

    monkeypatch.setattr(Toolwall, "__init__", spy)
    with pytest.raises(PolicyError, match=r"\$"):
        Toolwall.from_file(path)
    assert constructed is False


def test_non_mapping_yaml_refuses_to_return_partial_policies(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("- version\n- 1\n", encoding="utf-8")
    result = None
    with pytest.raises(PolicyError, match=r"\$"):
        result = load_policy_file(path)
    assert result is None


def test_empty_yaml_refuses_to_return_partial_policies(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("", encoding="utf-8")
    result = None
    with pytest.raises(PolicyError, match=r"\$"):
        result = load_policy_file(path)
    assert result is None


def test_json_and_yaml_load_identically(tmp_path: Path) -> None:
    data = {
        "version": 1,
        "default": "deny",
        "tools": {
            "read_file": {
                "allow": True,
                "args": {"path": {"matches": "^/workspace/"}},
            }
        },
    }
    yaml_path = write_yaml(tmp_path, data)
    json_path = tmp_path / "policy.json"
    json_path.write_text(json.dumps(data), encoding="utf-8")
    yaml_wall = Toolwall.from_file(yaml_path)
    json_wall = Toolwall.from_file(json_path)
    for tool, args in [
        ("read_file", {"path": "/workspace/a"}),
        ("read_file", {"path": "/etc/a"}),
        ("unknown", {}),
    ]:
        yaml_decision = yaml_wall.check(tool, args)
        json_decision = json_wall.check(tool, args)
        assert (yaml_decision.effect, yaml_decision.policy) == (
            json_decision.effect,
            json_decision.policy,
        )
