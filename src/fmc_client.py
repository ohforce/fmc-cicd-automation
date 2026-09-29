import os
import requests
from dotenv import load_dotenv

load_dotenv()

FMC_HOST = os.getenv("FMC_HOST")
FMC_USERNAME = os.getenv("FMC_USERNAME")
FMC_PASSWORD = os.getenv("FMC_PASSWORD")

BASE_URL = f"https://{FMC_HOST}"

session = requests.Session()

# FMC 인증서 검증을 기본적으로 비활성화
session.verify = False

def authenticate():
    url = f"{BASE_URL}/api/fmc_platform/v1/auth/generatetoken"

    response = session.post(
        url,
        auth=(FMC_USERNAME, FMC_PASSWORD),
        timeout=30
    )

    response.raise_for_status()

    token = response.headers.get("X-auth-access-token")
    domain_uuid = response.headers.get("DOMAIN_UUID")

    if not token:
        raise RuntimeError("FMC authentication token was not returned.")

    session.headers.update({
        "X-auth-access-token": token,
        "Content-Type": "application/json"
    })

    return domain_uuid


def get_api_data(endpoint, params=None):
    url = f"{BASE_URL}{endpoint}"

    response = session.get(
        url,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response.json()