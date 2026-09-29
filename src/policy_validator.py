def validate_rule(rule):
    findings = []

    if (
        rule.get("action") == "ALLOW"
        and rule.get("source_any")
        and rule.get("destination_any")
        and rule.get("service_any")
    ):
        findings.append("ANY_ANY_ALLOW")

    if (
        rule.get("action") == "ALLOW"
        and rule.get("source_any")
    ):
        findings.append("ANY_SOURCE_ALLOW")

    if (
        rule.get("action") == "ALLOW"
        and rule.get("service_any")
    ):
        findings.append("ANY_SERVICE_ALLOW")

    if (
        rule.get("action") == "ALLOW"
        and rule.get("enabled")
        and not rule.get("logging")
    ):
        findings.append("ALLOW_WITHOUT_LOGGING")

    if not rule.get("enabled"):
        findings.append("DISABLED_RULE")

    return findings