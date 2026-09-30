# src/policy_validator.py

def validate_rule(rule):
    """
    FMC Access Control Rule 을 검증하여 보안 문제 (Finding) 를 반환합니다.
    """
    findings = []

    # Any-Any-Allow 감지 (가장 위험 - CRITICAL)
    if (
        rule.get("action") == "ALLOW"
        and rule.get("source_any")
        and rule.get("destination_any")
        and rule.get("service_any")
    ):
        findings.append({
            "finding": "ANY_ANY_ALLOW",
            "severity": "Critical",  # ← CI 실패 대상
            "recommendation": (
                "Review whether the rule can be restricted to specific "
                "source networks, destination networks, and required services."
            )
        })

    # Any-Source-Allow 감지 (Warning)
    if (
        rule.get("action") == "ALLOW"
        and rule.get("source_any")
        and not rule.get("destination_any")
    ):
        findings.append({
            "finding": "ANY_SOURCE_ALLOW",
            "severity": "Warning",  # ← 경고만
            "recommendation": (
                "Consider restricting source to specific networks or host groups."
            )
        })

    # Any-Destination-Allow 감지 (Warning)
    if (
        rule.get("action") == "ALLOW"
        and rule.get("destination_any")
        and not rule.get("source_any")
    ):
        findings.append({
            "finding": "ANY_DESTINATION_ALLOW",
            "severity": "Warning",
            "recommendation": (
                "Consider restricting destination to specific networks or host groups."
            )
        })

    # Any-Service-Allow 감지 (Warning)
    if (
        rule.get("action") == "ALLOW"
        and rule.get("service_any")
    ):
        findings.append({
            "finding": "ANY_SERVICE_ALLOW",
            "severity": "Warning",
            "recommendation": (
                "Restrict services to only required ports and protocols."
            )
        })

    return findings


def get_severity_level(severity):
    """심각도 레벨 반환 (숫자)"""
    levels = {
        "Critical": 3,
        "High": 2,
        "Warning": 1,
        "Info": 0
    }
    return levels.get(severity, 0)