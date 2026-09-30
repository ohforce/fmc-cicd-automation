# src/policy_audit.py

from fmc_client import authenticate, get_api_data
from policy_validator import validate_rule
from policy_report import generate_csv_report, generate_summary
import json
import sys
from pathlib import Path
from datetime import datetime


def load_exceptions():
    """예외 목록 로드"""
    exceptions_file = Path(__file__).parent.parent / "exceptions.json"
    
    if not exceptions_file.exists():
        return []
    
    with open(exceptions_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        return data.get("exceptions", [])


def is_exception(policy_name, rule_name, finding, exceptions):
    """예외 목록에 있는지 확인"""
    for exc in exceptions:
        if (
            exc.get("policy_name") == policy_name
            and exc.get("rule_name") == rule_name
            and exc.get("finding") == finding
        ):
            # 만료일 확인
            expiration = exc.get("expiration")
            if expiration:
                try:
                    if datetime.strptime(expiration, "%Y-%m-%d") < datetime.now():
                        continue  # 만료됨
                except:
                    pass
            return True
    return False


def audit_policies():
    """
    FMC 의 모든 Access Control Policy 를 감사하고 보고서를 생성합니다.
    """
    
    print("🔐 Authenticating to FMC...")
    domain_uuid = authenticate()
    print(f"✅ Authenticated. Domain UUID: {domain_uuid}")
    
    print("📋 Fetching access policies...")
    endpoint = f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies"
    policies_response = get_api_data(endpoint, params={"limit": 100})
    
    all_findings = []
    exceptions = load_exceptions()
    
    # 카운터
    total_rules = 0
    passed_rules = 0
    warnings = 0
    failed_rules = 0
    
    for policy in policies_response.get("items", []):
        policy_name = policy.get("name")
        policy_id = policy.get("id")
        print(f"\n🔍 Auditing policy: {policy_name}")
        
        # 정책 내  가져오기
        rules_endpoint = f"{endpoint}/{policy_id}/accessrules"
        rules_response = get_api_data(rules_endpoint, params={"limit": 1000})
        
        for rule in rules_response.get("items", []):
            rule_name = rule.get("name", "Unnamed Rule")
            rule_id = rule.get("id")
            total_rules += 1
            
            #  정보 추출
            rule_info = {
                "policy_name": policy_name,
                "policy_id": policy_id,
                "rule_name": rule_name,
                "rule_id": rule_id,
                "action": rule.get("action", "N/A"),
                "enabled": rule.get("enabled", False),
                "source_any": rule.get("sourceNetworks", {}).get("any", False),
                "destination_any": rule.get("destinationNetworks", {}).get("any", False),
                "service_any": rule.get("ports", {}).get("any", False),
            }
            
            # 소스/목적지/서비스 정보
            source_nets = rule.get("sourceNetworks", {}).get("objects", [])
            dest_nets = rule.get("destinationNetworks", {}).get("objects", [])
            services = rule.get("ports", {}).get("objects", [])
            
            rule_info["source"] = ", ".join([s.get("name", "Any") for s in source_nets]) or "Any"
            rule_info["destination"] = ", ".join([d.get("name", "Any") for d in dest_nets]) or "Any"
            rule_info["service"] = ", ".join([p.get("name", "Any") for p in services]) or "Any"
            
            # 룰 검증
            findings = validate_rule(rule_info)
            
            # findings 데이터 가공
            rule_has_critical = False
            rule_has_warning = False
            
            for finding in findings:
                # 예외 확인
                if is_exception(policy_name, rule_name, finding["finding"], exceptions):
                    print(f"  ⚪ EXCEPTED: {rule_name} - {finding['finding']} (Approved)")
                    continue
                
                finding_record = {
                    "policy_name": policy_name,
                    "rule_name": rule_name,
                    "rule_id": rule_id,
                    "source": rule_info["source"],
                    "destination": rule_info["destination"],
                    "service": rule_info["service"],
                    "action": rule_info["action"],
                    "finding": finding["finding"],
                    "severity": finding["severity"],
                    "recommendation": finding["recommendation"]
                }
                all_findings.append(finding_record)
                
                if finding["severity"] == "Critical":
                    rule_has_critical = True
                elif finding["severity"] == "Warning":
                    rule_has_warning = True
                
                print(f"  ⚠️  FOUND: {rule_name} - {finding['finding']} ({finding['severity']})")
            
            if not findings:
                passed_rules += 1
                print(f"  ✅ PASSED: {rule_name}")
            elif rule_has_critical:
                failed_rules += 1
            elif rule_has_warning:
                warnings += 1
                passed_rules += 1  # Warning 은 Pass 로 카운트
    
    # 보고서 생성 (항상)
    print(f"\n📊 Generating report with {len(all_findings)} finding(s)...")
    generate_csv_report(all_findings, "fmc_policy_report.csv")
    
    # 요약 정보 출력
    summary = generate_summary(all_findings)
    print("\n=== SUMMARY ===")
    print(f"Total Rules: {total_rules}")
    print(f"Passed: {passed_rules}")
    print(f"Warnings: {warnings}")
    print(f"Failed: {failed_rules}")
    
    # ✅ CI 결과 판단
    if failed_rules > 0:
        print("\n❌ Result: FAILED")
        print(f"\nCritical Findings:")
        for f in all_findings:
            if f["severity"] == "Critical":
                print(f"  - {f['policy_name']} / {f['rule_name']} : {f['finding']}")
        sys.exit(1)  # ← CI 실패
    else:
        print("\n✅ Result: PASSED")
        sys.exit(0)  # ← CI 성공
    
    return all_findings


if __name__ == "__main__":
    audit_policies()