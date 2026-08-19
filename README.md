# agent-toolwall

Agent Toolwall enforces explicit policy between an LLM agent's tool decision and the tool's execution.

- Allow or deny tools and validate their structured arguments.
- Rate-limit actions and escalate sensitive calls for human approval.
- Audit every decision, including allowed calls.

## Demo

```text
scenario               goal                  unprotected   protected   blocked by
exfil_email            data exfiltration     LEAKED        BLOCKED     arg_rules:send_email.to
exfil_url              data exfiltration     LEAKED        BLOCKED     arg_rules:http_get.url
unauthorized_purchase  unauthorized action   ORDERED       BLOCKED     sensitive:submit_order
destructive_write      destructive action    WRITTEN       BLOCKED     arg_rules:write_file.path
exfil_flood            resource abuse        20 requests   5 requests  rate_limit:http_get
benign_control         (legitimate task)     OK            OK          - (allowed)

blocked 5/5 attacks, allowed 1/1 benign task. audit: outputs/demo-audit.jsonl (26 records)
```

Run the same offline demo with `toolwall-demo`.

## Install

```sh
pip install -e .
```

## Usage

```python
from toolwall import Effect, Toolwall
from toolwall.policies import tool_allowlist

wall = Toolwall(
    [tool_allowlist(["read_file"])],
    default=Effect.DENY,
)

allowed = wall.check("read_file", {"path": "a"})
blocked = wall.check("send_email", {})

assert allowed.effect is Effect.ALLOW
assert blocked.effect is Effect.DENY
assert blocked.reason == "default"
print(allowed.effect.value, blocked.effect.value)
```

Use `decision.args`, not the original argument dict, when executing an allowed call. `Toolwall.call()` does this automatically and raises `ToolCallBlocked` for denied calls.

## Policy file

`Toolwall.from_file("policy.yaml")` loads YAML or JSON. The demo policy uses all four built-in policy shapes:

```yaml
version: 1
default: deny
audit:
  redact: [api_key, password]
tools:
  read_file:
    allow: true
    args:
      path: {type: str, required: true, matches: "^/workspace/"}
  http_get:
    allow: true
    rate_limit: {max: 5, per_seconds: 60, key: [session_id]}
    args:
      url: {type: str, required: true, allow_hosts: [".example.com", docs.python.org]}
  send_email:
    allow: true
    args:
      to: {type: str, required: true, allow_hosts: [example.com]}
  submit_order:
    allow: true
    sensitive: true
  write_file:
    allow: true
    args:
      path: {type: str, required: true, matches: "^/workspace/"}
  "*":
    args:
      "*": {denies: "CANARY-[0-9A-F]{4}"}
```

Policies fail closed on malformed config, unknown keys, policy exceptions, ambiguous normalized argument keys, and unsafe escalation results. Rate limits are in-process only.

## Integration

Raw OpenAI/Anthropic tool-call loop (after normalizing each provider's call object to `name` and `arguments`):

```python
for call in response.tool_calls:
    decision = wall.check(call.name, call.arguments)
    if decision.effect is not Effect.ALLOW:
        continue
    results.append(tools[call.name](**decision.args))
```

Generic `dispatch(name, args)` router:

```python
def dispatch(name, args):
    decision = wall.check(name, args)
    if decision.effect is not Effect.ALLOW:
        raise ToolCallBlocked(decision)
    return tools[name](**decision.args)
```

MCP-style server boundary:

```python
@server.call_tool()
def call_tool(name, arguments):
    decision = wall.check(name, arguments)
    if decision.effect is not Effect.ALLOW: raise ToolCallBlocked(decision)
    return mcp_tools[name](**decision.args)
```

## What this is not

Toolwall is not a content filter: it never sees prompts, completions, or tool results. It is not a sandbox or capability boundary: it governs only calls the trusted application routes through `check()` or `call()`. It is not an injection detector: it constrains consequences after the model has chosen concrete tool arguments.

Its threat model trusts the application and policy file, but not model decisions. Tool access through another client, a shell, an unwrapped SDK, or any other bypass remains unprotected. Harm that fits entirely inside allowed tools and arguments remains possible: a permitted email can still be misleading. A compromised policy file is equivalent to disabling the firewall. Pair Toolwall with process isolation, least-privilege credentials, and content-layer defenses where those risks matter.

## Relationship to agent-injection-bench

[`agent-injection-bench`](https://github.com/euisuh/agent-injection-bench) is the offense and measurement sibling: it measures whether indirect prompt injection persuades models and how mitigations affect attack success. This repository is defense and systems-building: given a concrete tool call, it enforces policy before the side effect. Together they measure the problem, then ship part of the fix; Toolwall's demo mirrors the same threat shapes without importing benchmark code or claiming susceptibility rates.
