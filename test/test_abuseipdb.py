import sys
sys.path.append('/app')

import pytest
from aiohttp import ClientSession
from aioresponses import aioresponses

from ipcheckers.abuseipdb import make_request_abuse, get_abuseipdb_info, gen_result, determine_verdict_abuseipdb

# Константы для моков
MOCK_KEY = "mock_abuseipdb_key"
MOCK_URL = "https://api.abuseipdb.com/api/v2/check"
MOCK_IP = "192.168.0.1"
MOCK_RESPONSE = {
    "data": {
        "ipAddress": MOCK_IP,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 75,
        "countryCode": "US",
        "usageType": "ISP",
        "isp": "Mock ISP",
        "domain": "mockdomain.com",
        "totalReports": 15,
        "numDistinctUsers": 10
    }
}

@pytest.fixture
def mock_keys(monkeypatch):
    """Подмена конфигурации API-ключей и URL."""
    monkeypatch.setattr('config.config.KEYS', {'ABUSEIPDB_KEY': MOCK_KEY})
    monkeypatch.setattr('config.config.URLS', {'API_URL_ABUSEIPDB': MOCK_URL})

@pytest.mark.asyncio
async def test_make_request_abuse(mock_keys):
    """Тест функции make_request_abuse."""
    with aioresponses() as m:
        m.get(
            f"{MOCK_URL}?ipAddress={MOCK_IP}&maxAgeInDays=90",
            payload=MOCK_RESPONSE
        )

        async with ClientSession() as session:
            result = await make_request_abuse(session, MOCK_IP)

        expected = {
            "ip_address": MOCK_IP,
            "is_public": True,
            "ip_version": 4,
            "is_whitelisted": False,
            "abuse_confidence_score": 75,
            "country": "🇺🇸 US",
            "usage_type": "ISP",
            "isp": "Mock ISP",
            "domain": "mockdomain.com",
            "total_reports": 15,
            "num_distinct_users": 10,
            "verdict": "🔴 malicious"
        }
        assert result == expected

@pytest.mark.asyncio
async def test_get_abuseipdb_info(mock_keys):
    """Тест функции get_abuseipdb_info."""
    with aioresponses() as m:
        m.get(
            f"{MOCK_URL}?ipAddress={MOCK_IP}&maxAgeInDays=90",
            payload=MOCK_RESPONSE
        )
        m.get(
            f"{MOCK_URL}?ipAddress=8.8.8.8&maxAgeInDays=90",
            payload=MOCK_RESPONSE
        )

        ips = [MOCK_IP, "8.8.8.8"]
        async with ClientSession() as session:
            success, results = await get_abuseipdb_info(ips, [])

        assert success is True
        assert len(results) == 2
        for result in results:
            assert result["ip_address"] in ips

def test_gen_result():
    """Тест функции gen_result."""
    result = gen_result(MOCK_RESPONSE["data"])
    expected = {
        "ip_address": MOCK_IP,
        "is_public": True,
        "ip_version": 4,
        "is_whitelisted": False,
        "abuse_confidence_score": 75,
        "country": "🇺🇸 US",
        "usage_type": "ISP",
        "isp": "Mock ISP",
        "domain": "mockdomain.com",
        "total_reports": 15,
        "num_distinct_users": 10,
        "verdict": "🔴 malicious"
    }
    assert result == expected

def test_determine_verdict_abuseipdb():
    """Тест функции determine_verdict_abuseipdb."""
    assert determine_verdict_abuseipdb(0, 0) == "⚫️ undetected"
    assert determine_verdict_abuseipdb(30, 1) == "🟡 suspicious"
    assert determine_verdict_abuseipdb(70, 5) == "🔴 malicious"
    assert determine_verdict_abuseipdb(10, 15) == "🔴 malicious"
