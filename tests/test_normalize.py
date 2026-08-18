from toolwall import Effect, Toolwall
from toolwall.policies import arg_rules


def wall(rules):
    return Toolwall([arg_rules(rules)], default=Effect.ALLOW)


def test_tool_name_nfkc_and_casefold_hits_send_email_rule() -> None:
    policy = wall({"send_email": {"to": {"denies": "blocked"}}})
    assert policy.check("SEND_EMAIL", {"to": "blocked"}).effect is Effect.DENY
    assert (
        policy.check("ｓｅｎｄ＿ｅｍａｉｌ", {"to": "blocked"}).effect
        is Effect.DENY
    )


def test_cyrillic_o_key_alongside_ascii_to_denies_ambiguity() -> None:
    decision = wall({"send_email": {"to": {"required": True}}}).check(
        "send_email", {"to": "a", "tо": "b"}
    )
    assert decision.effect is Effect.DENY
    assert decision.reason.startswith("ambiguous argument keys:")
    assert "to" in decision.reason
    assert "tо" in decision.reason


def test_cyrillic_o_key_alone_matches_ascii_to_rule() -> None:
    decision = wall({"send_email": {"to": {"denies": "blocked"}}}).check(
        "send_email", {"tо": "blocked"}
    )
    assert decision.effect is Effect.DENY
    assert decision.policy == "arg_rules:send_email.to"


def test_deny_pattern_found_inside_nested_list() -> None:
    decision = wall({"*": {"*": {"denies": "CANARY-7F3A"}}}).check(
        "tool", {"data": ["safe", ["CANARY-7F3A"]]}
    )
    assert decision.effect is Effect.DENY


def test_deny_pattern_found_inside_nested_dict_value() -> None:
    decision = wall({"*": {"*": {"denies": "CANARY-7F3A"}}}).check(
        "tool", {"data": {"meta": {"payload": "CANARY-7F3A"}}}
    )
    assert decision.effect is Effect.DENY


def test_nfkc_normalized_argument_value_matches_pattern() -> None:
    decision = wall({"*": {"*": {"denies": "SECRET"}}}).check(
        "tool", {"data": "ＳＥＣＲＥＴ"}
    )
    assert decision.effect is Effect.DENY


def test_depth_limit_exceeded_denies_instead_of_truncating() -> None:
    value = "safe"
    for _ in range(21):
        value = [value]
    decision = wall({"*": {"*": {"denies": "never"}}}).check(
        "tool", {"data": value}
    )
    assert decision.effect is Effect.DENY
    assert decision.reason == "argument value depth exceeds 20"


def test_string_count_limit_exceeded_denies_instead_of_truncating() -> None:
    decision = wall({"*": {"*": {"denies": "never"}}}).check(
        "tool", {"data": ["safe"] * 10_001}
    )
    assert decision.effect is Effect.DENY
    assert decision.reason == "argument value string count exceeds 10000"

