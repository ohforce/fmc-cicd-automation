import csv
import os

# 결과 저장 폴더
os.makedirs("reports", exist_ok=True)

# CSV 파일 생성
with open("reports/policy_validation_report.csv", "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.writer(f)

    # 헤더 (이미지와 동일)
    writer.writerow([
        "Policy", "Rule Name", "Rule ID", "Source",
        "Destination", "Service", "Action", "Finding",
        "Severity", "Remediation Recommendation"
    ])

    # 예시 데이터 (네가 실제 FMC + validator 결과로 채우면 됨)
    # 이미지의 예시를 참고로 넣음
    writer.writerow([
        "Corporate Policy",
        "Allow Any Traffic",
        "005056AB-1234-5678-0000-000000000001",
        "Any",
        "Any",
        "Any",
        "ALLOW",
        "ANY_ANY_ALLOW",
        "High",
        "Review whether the rule can be restricted to specific source networks, destination networks, and required services."
    ])

    writer.writerow([
        "Corporate Policy",
        "Any Source HTTPS",
        "005056AB-1234-5678-0000-000000000002",
        "Any",
        "Specific",
        "HTTPS",
        "ALLOW",
        "ANY_SOURCE_ALLOW",
        "Medium",
        "Restrict source networks to required internal or partner IP ranges."
    ])

    writer.writerow([
        "Guest Policy",
        "Allow All Services",
        "005056AB-1234-5678-0000-000000000003",
        "Any",
        "Any",
        "Any",
        "ALLOW",
        "ANY_SERVICE_ALLOW",
        "High",
        "Limit services to only those required for guest access."
    ])

print("Report generated: reports/policy_validation_report.csv")