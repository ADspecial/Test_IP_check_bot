import sys
sys.path.append('C:\\Users\\d.lekontsev\\Documents\\Development\\Test_IP_check_bot')

import aiohttp
import pytest
import asyncio
from aioresponses import aioresponses
from ipcheckers.abuseipdb import make_request_abuse, get_abuseipdb_info  # Замените your_module на имя вашего модуля
from config.config import KEYS, URLS

@pytest.mark.asyncio
async def test_make_request_abuse():
    ip = "8.8.8.8"
    expected_result = {
        "ip_address": "8.8.8.8",
        "is_public": True,
        "ip_version": 4,
        "is_whitelisted": False,
        "abuse_confidence_score": 50,
        "country": "🇺🇸",
        "usage_type": "search engine",
        "isp": "Google LLC",
        "domain": "google.com",
        "total_reports": 5,
        "num_distinct_users": 3,
        "verdict": "🟡 suspicious"
    }

    with aioresponses() as m:
        m.get(URLS.API_URL_ABUSEIPDB, payload={'data': expected_result})

        async with aiohttp.ClientSession() as session:
            result = await make_request_abuse(session, ip)
            assert result == expected_result

@pytest.mark.asyncio
async def test_get_abuseipdb_info():
    ips = ["8.8.8.8", "1.1.1.1"]
    expected_results = [
        {
            "ip_address": "8.8.8.8",
            "is_public": True,
            "ip_version": 4,
            "is_whitelisted": False,
            "abuse_confidence_score": 50,
            "country": "🇺🇸",
            "usage_type": "search engine",
            "isp": "Google LLC",
            "domain": "google.com",
            "total_reports": 5,
            "num_distinct_users": 3,
            "verdict": "🟡 suspicious"
        },
        {
            # Добавьте ожидаемый результат для второго IP
        }
    ]

    with aioresponses() as m:
        m.get(URLS.API_URL_ABUSEIPDB, payload={'data': expected_results[0]})
        m.get(URLS.API_URL_ABUSEIPDB, payload={'data': expected_results[1]})

        success, results = await get_abuseipdb_info(ips, [])

        assert success is True
        assert results == expected_results
