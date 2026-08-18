from detection_engine.engine import run_detections
from detection_engine.loader import load_rules, load_samples
from detection_engine.validate import collect_errors


def test_detections_tree_is_valid() -> None:
    assert collect_errors() == []


def test_every_rule_has_sql_and_loads() -> None:
    rules = load_rules()
    assert len(rules) == 8
    assert all(rule.sql_path and rule.sql_path.is_file() for rule in rules)
    assert {rule.product for rule in rules} == {"okta", "aws"}


def test_sample_events_produce_expected_alerts() -> None:
    alerts = run_detections()
    observed = {(alert.event_id, alert.rule.id) for alert in alerts}

    expected: set[tuple[str, str]] = set()
    for sample in load_samples():
        expected.update(sample.expected_alerts)

    assert expected, "sample fixtures must declare expected_alerts"
    assert observed == expected


def test_okta_rules_do_not_fire_on_aws_events() -> None:
    alerts = run_detections()
    for alert in alerts:
        if alert.sample.logsource == "aws":
            assert alert.rule.product == "aws"
        if alert.sample.logsource == "okta":
            assert alert.rule.product == "okta"
