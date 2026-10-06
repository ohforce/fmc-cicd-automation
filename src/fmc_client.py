# src/fmc_client.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()

FMC_HOST = os.getenv("FMC_HOST")
FMC_USERNAME = os.getenv("FMC_USERNAME")
FMC_PASSWORD = os.getenv("FMC_PASSWORD")

# 디버깅: 환경 변수 확인
if not FMC_HOST:
    raise RuntimeError("FMC_HOST is not set in environment variables.")

BASE_URL = f"https://{FMC_HOST}"

session = requests.Session()

# FMC 인증서 검증 (개발 환경에서는 False, 프로덕션에서는 True + CA 인증서)
session.verify = False

def authenticate():
    """
    FMC 에 인증하고 토큰을 얻습니다.
    """
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
    """
    FMC API 에서 데이터를 가져옵니다.
    """
    url = f"{BASE_URL}{endpoint}"

    response = session.get(
        url,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response.json()