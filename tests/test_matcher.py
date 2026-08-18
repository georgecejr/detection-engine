from pathlib import Path

import pytest
from detection_engine.matcher import lookup, matches, selection_matches
from detection_engine.models import Rule

EVENT = {
    "eventType": "user.account.privilege.grant",
    "debugContext": {"debugData": {"privilegeGranted": "Super Administrator"}},
    "target": [{"displayName": "Jordan Lee", "alternateId": "jordan.lee@example.com"}],
}


def _rule(detection: dict) -> Rule:
    return Rule(
        path=Path("okta_admin.yml"),
        title="test",
        id="00000000-0000-0000-0000-000000000000",
        detection=detection,
        logsource={"product": "okta"},
    )


def test_lookup_is_case_insensitive_and_walks_nested_objects() -> None:
    values = lookup(EVENT, "debugcontext.debugdata.privilegegranted")
    assert values == ["Super Administrator"]


def test_lookup_walks_lists_of_objects() -> None:
    assert lookup(EVENT, "target.alternateid") == ["jordan.lee@example.com"]


def test_selection_equals_and_list_or() -> None:
    assert selection_matches(EVENT, {"eventtype": "user.account.privilege.grant"})
    assert selection_matches(
        EVENT,
        {"eventtype": ["user.account.privilege.grant", "iam.role.assign"]},
    )
    assert not selection_matches(EVENT, {"eventtype": "user.lifecycle.create"})


def test_contains_modifier() -> None:
    assert selection_matches(
        EVENT,
        {"debugcontext.debugdata.privilegegranted|contains": "Super Administrator"},
    )
    assert not selection_matches(
        EVENT,
        {"debugcontext.debugdata.privilegegranted|contains": "Read Only"},
    )


def test_and_condition() -> None:
    rule = _rule(
        {
            "selection": {"eventtype": "user.account.privilege.grant"},
            "filter_admin": {
                "debugcontext.debugdata.privilegegranted|contains": [
                    "Super Administrator"
                ]
            },
            "condition": "selection and filter_admin",
        }
    )
    assert matches(rule, EVENT)
    assert not matches(rule, {"eventType": "user.account.privilege.grant"})


def test_unknown_condition_identifier_raises() -> None:
    rule = _rule({"selection": {"eventtype": "x"}, "condition": "selection and missing"})
    with pytest.raises(ValueError, match="unknown detection identifier"):
        matches(rule, {"eventtype": "x"})
