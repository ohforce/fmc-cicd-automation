from src.policy_validator import validate_rule


def test_detect_any_any_allow():
    rule = {
        "name": "Allow Any Traffic",
        "action": "ALLOW",
        "source_any": True,
        "destination_any": True,
        "service_any": True,
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    assert "ANY_ANY_ALLOW" in findings


def test_detect_any_source_allow():
    rule = {
        "name": "Any Source",
        "action": "ALLOW",
        "source_any": True,
        "destination_any": False,
        "service_any": False,
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    assert "ANY_SOURCE_ALLOW" in findings


def test_no_findings_for_restricted_rule():
    rule = {
        "name": "Approved HTTPS Rule",
        "action": "ALLOW",
        "source_any": False,
        "destination_any": False,
        "service_any": False,
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    assert findings == []