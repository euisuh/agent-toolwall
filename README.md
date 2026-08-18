# agent-toolwall

Policy enforcement between an LLM agent's tool decision and tool execution.

## Quickstart

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
