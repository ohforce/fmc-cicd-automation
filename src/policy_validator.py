def validate_rule(rule):
    findings = []

    # 1. ANY_ANY_ALLOW
    if (rule.get("action") == "ALLOW" and
        rule.get("source_any") is True and
        rule.get("destination_any") is True and
        rule.get("service_any") is True and
        rule.get("enabled") is True and
        rule.get("logging") is True):
        findings.append("ANY_ANY_ALLOW")

    # 2. ANY_SOURCE_ALLOW
    if (rule.get("action") == "ALLOW" and
        rule.get("source_any") is True and
        rule.get("destination_any") is False and
        rule.get("service_any") is False and
        rule.get("enabled") is True and
        rule.get("logging") is True):
        findings.append("ANY_SOURCE_ALLOW")

    # 3. ANY_SERVICE_ALLOW
    if (rule.get("action") == "ALLOW" and
        rule.get("source_any") is False and
        rule.get("destination_any") is False and
        rule.get("service_any") is True and
        rule.get("enabled") is True and
        rule.get("logging") is True):
        findings.append("ANY_SERVICE_ALLOW")

    return findings