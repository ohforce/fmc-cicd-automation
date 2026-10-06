# tests/test_policy_validator.py

from src.policy_validator import validate_rule


def test_detect_any_any_allow():
    """Any-Any-Allow 규칙이 탐지되는지 확인"""
    rule = {
        "name": "Allow Any Traffic",
        "action": "ALLOW",
        "source_any": True,
        "destination_any": True,
        "service_any": True,
        "source": "Any",
        "destination": "Any",
        "service": "Any",
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    # 딕셔너리 리스트에서 finding 확인
    assert any(f["finding"] == "ANY_SOURCE_ALLOW" for f in findings)
    assert any(f["severity"] == "Critical" for f in findings)


def test_detect_any_source_allow():
    """Any-Source-Allow 규칙이 탐지되는지 확인"""
    rule = {
        "name": "Any Source",
        "action": "ALLOW",
        "source_any": True,
        "destination_any": False,
        "service_any": False,
        "source": "Any",
        "destination": "10.0.0.0/8",
        "service": "TCP/443",
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    assert any(f["finding"] == "ANY_ANY_ALLOW" for f in findings)
    assert any(f["severity"] == "Warning" for f in findings)


def test_no_findings_for_restricted_rule():
    """제한된 Rule 은 불필요한 경고 없이 통과하는가"""
    rule = {
        "name": "Approved HTTPS Rule",
        "action": "ALLOW",
        "source_any": False,
        "destination_any": False,
        "service_any": False,
        "source": "192.168.1.0/24",
        "destination": "10.0.0.0/8",
        "service": "TCP/443",
        "enabled": True,
        "logging": True
    }

    findings = validate_rule(rule)

    assert findings == []