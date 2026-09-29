from fmc_client import authenticate, get_api_data

domain_uuid = authenticate()

endpoint = (
    f"/api/fmc_config/v1/domain/{domain_uuid}"
    "/policy/accesspolicies"
)

data = get_api_data(
    endpoint,
    params={"limit": 100, "offset": 0}
)

for policy in data.get("items", []):
    print(
        policy.get("name"),
        policy.get("id")
    )