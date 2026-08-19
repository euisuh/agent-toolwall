"""Strict YAML/JSON policy loading."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import yaml

from .audit import AuditLog
from .policies import arg_rules, rate_limit, sensitive, tool_allowlist, tool_denylist
from .types import Effect, Policy, PolicyError


_TOP_KEYS = {"version", "default", "audit", "tools"}
_TOOL_KEYS = {"allow", "args", "rate_limit", "sensitive"}
_ARG_KEYS = {
    "required",
    "type",
    "max_len",
    "enum",
    "matches",
    "denies",
    "allow_hosts",
    "on_violation",
}
_RATE_KEYS = {"max", "per_seconds", "key"}
_AUDIT_KEYS = {"path", "redact"}
_TYPES = {"str", "int", "float", "bool", "list", "dict"}


def _error(path: str, message: str) -> PolicyError:
    return PolicyError(f"{path}: {message}")


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(path, "must be a mapping")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], path: str) -> None:
    for key in value:
        if not isinstance(key, str) or key not in allowed:
            child = f"{path}.{key}" if path else str(key)
            raise _error(child, "unknown key")


def _validate_constraint(value: Any, path: str) -> dict[str, Any]:
    constraint = _mapping(value, path)
    _reject_unknown(constraint, _ARG_KEYS, path)
    if "type" in constraint and (
        not isinstance(constraint["type"], str) or constraint["type"] not in _TYPES
    ):
        raise _error(f"{path}.type", f"unsupported type {constraint['type']!r}")
    for key in ("matches", "denies"):
        if key in constraint:
            pattern = constraint[key]
            if not isinstance(pattern, str):
                raise _error(f"{path}.{key}", "must be a string")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise _error(f"{path}.{key}", f"invalid regex: {exc}") from exc
    if "allow_hosts" in constraint and (
        not isinstance(constraint["allow_hosts"], list)
        or any(
            not isinstance(host, str) or not host
            for host in constraint["allow_hosts"]
        )
    ):
        raise _error(f"{path}.allow_hosts", "must be a list of non-empty strings")
    if "enum" in constraint and not isinstance(constraint["enum"], list):
        raise _error(f"{path}.enum", "must be a list")
    if "required" in constraint and not isinstance(constraint["required"], bool):
        raise _error(f"{path}.required", "must be a boolean")
    if "max_len" in constraint and (
        type(constraint["max_len"]) is not int or constraint["max_len"] < 0
    ):
        raise _error(f"{path}.max_len", "must be a non-negative integer")
    if constraint.get("on_violation") not in (None, "deny", "redact"):
        raise _error(f"{path}.on_violation", "must be 'deny' or 'redact'")
    return constraint


def _validate_args(value: Any, path: str) -> dict[str, dict[str, Any]]:
    args = _mapping(value, path)
    validated = {}
    for name, constraint in args.items():
        if not isinstance(name, str):
            raise _error(f"{path}.{name}", "argument name must be a string")
        validated[name] = _validate_constraint(constraint, f"{path}.{name}")
    return validated


def _validate_rate(value: Any, path: str) -> dict[str, Any]:
    rate = _mapping(value, path)
    _reject_unknown(rate, _RATE_KEYS, path)
    if type(rate.get("max")) is not int or rate["max"] <= 0:
        raise _error(f"{path}.max", "must be a positive integer")
    per_seconds = rate.get("per_seconds")
    if (
        isinstance(per_seconds, bool)
        or not isinstance(per_seconds, (int, float))
        or per_seconds <= 0
    ):
        raise _error(f"{path}.per_seconds", "must be a positive number")
    key = rate.get("key", [])
    if not isinstance(key, list) or any(not isinstance(item, str) for item in key):
        raise _error(f"{path}.key", "must be a list of strings")
    return rate


def _validate_audit(value: Any) -> dict[str, Any]:
    audit = _mapping(value, "audit")
    _reject_unknown(audit, _AUDIT_KEYS, "audit")
    if "path" in audit and not isinstance(audit["path"], str):
        raise _error("audit.path", "must be a string")
    redact = audit.get("redact", [])
    if not isinstance(redact, list) or any(not isinstance(item, str) for item in redact):
        raise _error("audit.redact", "must be a list of strings")
    return audit


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as file:
            data = (
                json.load(file)
                if path.suffix.casefold() == ".json"
                else yaml.safe_load(file)
            )
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise _error("$", f"cannot load policy: {exc}") from exc
    return _mapping(data, "$")


def _named(policy: Policy, name: str) -> Policy:
    setattr(policy, "_toolwall_name", name)
    return policy


def load_policy_file(path: str | Path) -> tuple[list[Policy], Effect, AuditLog | None]:
    """Load and fully validate a policy file before returning any policies."""
    data = _load(Path(path))
    _reject_unknown(data, _TOP_KEYS, "")
    if data.get("version") != 1 or type(data.get("version")) is not int:
        raise _error("version", "must be 1")
    if "default" not in data:
        raise _error("default", "is required")
    if not isinstance(data["default"], str) or data["default"] not in {
        "allow",
        "deny",
    }:
        raise _error("default", "must be 'deny' or 'allow'")

    tools = _mapping(data.get("tools", {}), "tools")
    validated: dict[str, dict[str, Any]] = {}
    for name, raw_block in tools.items():
        if not isinstance(name, str):
            raise _error(f"tools.{name}", "tool name must be a string")
        block = _mapping(raw_block, f"tools.{name}")
        _reject_unknown(block, _TOOL_KEYS, f"tools.{name}")
        if "allow" in block and not isinstance(block["allow"], bool):
            raise _error(f"tools.{name}.allow", "must be a boolean")
        if "sensitive" in block and not isinstance(block["sensitive"], bool):
            raise _error(f"tools.{name}.sensitive", "must be a boolean")
        item = dict(block)
        if "args" in block:
            item["args"] = _validate_args(block["args"], f"tools.{name}.args")
        if "rate_limit" in block:
            item["rate_limit"] = _validate_rate(
                block["rate_limit"], f"tools.{name}.rate_limit"
            )
        validated[name] = item

    audit_config = _validate_audit(data["audit"]) if "audit" in data else None
    policies: list[Policy] = []
    global_args = validated.get("*", {}).get("args")
    if global_args:
        policies.append(_named(arg_rules({"*": global_args}), "arg_rules:*"))

    allowed = [
        name
        for name, block in validated.items()
        if name != "*" and block.get("allow") is True
    ]
    denied = [
        name
        for name, block in validated.items()
        if name != "*" and block.get("allow") is False
    ]
    if allowed:
        policies.append(
            _named(tool_allowlist(allowed), f"tool_allowlist:{','.join(allowed)}")
        )
    if denied:
        policies.append(
            _named(tool_denylist(denied), f"tool_denylist:{','.join(denied)}")
        )

    specific_args = {
        name: block["args"]
        for name, block in validated.items()
        if name != "*" and block.get("args")
    }
    if specific_args:
        policies.append(
            _named(arg_rules(specific_args), f"arg_rules:{','.join(specific_args)}")
        )

    for name, block in validated.items():
        if name == "*" or "rate_limit" not in block:
            continue
        rate = block["rate_limit"]
        policies.append(
            _named(
                rate_limit(
                    name, rate["max"], rate["per_seconds"], rate.get("key", [])
                ),
                f"rate_limit:{name}",
            )
        )
    sensitive_tools = [
        name
        for name, block in validated.items()
        if name != "*" and block.get("sensitive") is True
    ]
    if sensitive_tools:
        policies.append(
            _named(sensitive(sensitive_tools), f"sensitive:{','.join(sensitive_tools)}")
        )

    try:
        audit = AuditLog(**audit_config) if audit_config is not None else None
    except OSError as exc:
        raise _error("audit.path", f"cannot open audit log: {exc}") from exc
    return policies, Effect(data["default"]), audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", metavar="PATH", required=True)
    args = parser.parse_args(argv)
    try:
        policies, _, _ = load_policy_file(args.validate)
    except PolicyError as exc:
        print(exc, file=sys.stderr)
        return 1
    for policy in policies:
        print(getattr(policy, "_toolwall_name"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
