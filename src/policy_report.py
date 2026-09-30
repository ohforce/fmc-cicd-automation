# src/policy_report.py

import csv
import os
from datetime import datetime
from pathlib import Path


def generate_csv_report(findings_data, output_file="fmc_policy_report.csv"):
    """
    검증 결과를 CSV 파일로 저장합니다.
    """
    
    # 프로젝트 루트 경로를 자동으로 찾음 (src 의 상위 폴더)
    project_root = Path(__file__).parent.parent
    output_path = project_root / output_file
    
    # CSV 헤더 정의
    fieldnames = [
        "Policy Name",
        "Rule Name",
        "Rule ID",
        "Source",
        "Destination",
        "Service",
        "Action",
        "Finding",
        "Severity",
        "Remediation Recommendation"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for finding in findings_data:
            writer.writerow({
                "Policy Name": finding.get("policy_name", "N/A"),
                "Rule Name": finding.get("rule_name", "N/A"),
                "Rule ID": finding.get("rule_id", "N/A"),
                "Source": finding.get("source", "Any"),
                "Destination": finding.get("destination", "Any"),
                "Service": finding.get("service", "Any"),
                "Action": finding.get("action", "N/A"),
                "Finding": finding.get("finding", "None"),
                "Severity": finding.get("severity", "N/A"),
                "Remediation Recommendation": finding.get("recommendation", "N/A")
            })
    
    print(f"✅ Report generated: {output_path}")
    return output_path


def generate_summary(findings_data):
    """
    검증 결과 요약 정보를 반환합니다.
    """
    total_rules = len(findings_data)
    total_findings = sum(
        1 for f in findings_data 
        if f.get("finding") and f.get("finding") != "None"
    )
    
    severity_count = {}
    for f in findings_data:
        sev = f.get("severity", "N/A")
        if sev and sev != "N/A":
            severity_count[sev] = severity_count.get(sev, 0) + 1
    
    return {
        "total_rules": total_rules,
        "total_findings": total_findings,
        "severity_breakdown": severity_count,
        "generated_at": datetime.now().isoformat()
    }