from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from toolwall.engine import Toolwall
from toolwall.policies import arg_rules, rate_limit
from toolwall.types import Effect


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def wall(max_calls=3, per_seconds=60, *, clock=None, key=()):
    return Toolwall(
        [rate_limit("send", max_calls, per_seconds, key, clock or Clock())],
        default=Effect.ALLOW,
    )


def test_first_three_calls_allow_and_fourth_denies():
    limiter = wall()

    decisions = [limiter.check("send", {}) for _ in range(4)]
    assert [decision.effect for decision in decisions] == [
        Effect.ALLOW,
        Effect.ALLOW,
        Effect.ALLOW,
        Effect.DENY,
    ]
    assert decisions[-1].policy == "rate_limit:send"
    assert "3 calls per 60 seconds" in decisions[-1].reason


def test_advancing_clock_past_window_reallows():
    clock = Clock()
    limiter = wall(1, clock=clock)

    assert limiter.check("send", {}).effect is Effect.ALLOW
    assert limiter.check("send", {}).effect is Effect.DENY
    clock.now = 61
    assert limiter.check("send", {}).effect is Effect.ALLOW


def test_calls_denied_by_earlier_policy_do_not_consume_budget():
    clock = Clock()
    limiter = Toolwall(
        [
            arg_rules({"send": {"to": {"required": True}}}),
            rate_limit("send", 3, 60, clock=clock),
        ],
        default=Effect.ALLOW,
    )

    assert all(limiter.check("send", {}).effect is Effect.DENY for _ in range(5))
    assert all(
        limiter.check("send", {"to": "ok"}).effect is Effect.ALLOW
        for _ in range(3)
    )
    assert limiter.check("send", {"to": "ok"}).effect is Effect.DENY


def test_rejected_attempts_do_not_extend_window():
    clock = Clock()
    limiter = wall(1, clock=clock)

    assert limiter.check("send", {}).effect is Effect.ALLOW
    for now in (10, 20, 30, 40, 50, 60):
        clock.now = now
        assert limiter.check("send", {}).effect is Effect.DENY
    clock.now = 61
    assert limiter.check("send", {}).effect is Effect.ALLOW


def test_context_key_isolates_sessions():
    limiter = wall(1, key=("session_id",))

    assert limiter.check("send", {}, {"session_id": "A"}).effect is Effect.ALLOW
    assert limiter.check("send", {}, {"session_id": "A"}).effect is Effect.DENY
    assert limiter.check("send", {}, {"session_id": "B"}).effect is Effect.ALLOW


def test_concurrent_calls_allow_exactly_the_limit():
    limiter = wall(50)
    barrier = Barrier(8)

    def issue_calls():
        barrier.wait()
        return sum(
            limiter.check("send", {}).effect is Effect.ALLOW for _ in range(100)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        allowed = sum(pool.map(lambda _: issue_calls(), range(8)))

    assert allowed == 50
