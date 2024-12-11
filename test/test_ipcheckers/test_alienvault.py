import sys
sys.path.append('/app')

import pytest
import asyncio
from aiohttp import ClientSession
from aioresponses import aioresponses
from datetime import datetime, timedelta

from ipcheckers.alienvault import make_request_alienvault, get_alienvault_info, gen_result

# Константы для моков
MOCK_KEY = "mock_alienvault_key"
MOCK_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
MOCK_IP = "192.168.0.1"
MOCK_RESPONSE = {
    "indicator": MOCK_IP,
    "country_code": "US",
    "asn": "Mock ASN",
    "pulse_info": {
        "pulses": [
            {
                "tags": ["malicious", "botnet"],
                "modified": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
            },
            {
                "tags": ["scan", "attack"],
                "modified": (datetime.now() - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S")
            }
        ]
    }
}

@pytest.fixture
def mock_keys(monkeypatch):
    """Подмена конфигурации API-ключей и URL."""
    monkeypatch.setattr('config.config.KEYS', {'ALIENVAULT_KEY': MOCK_KEY})
    monkeypatch.setattr('config.config.URLS', {'API_URL_ALIENVAULT': MOCK_URL})

@pytest.mark.asyncio
async def test_make_request_alienvault(mock_keys):
    """Тест функции make_request_alienvault."""
    with aioresponses() as m:
        m.get(
            f"{MOCK_URL}{MOCK_IP}/general",
            payload=MOCK_RESPONSE
        )

        result = await make_request_alienvault(MOCK_IP)

        expected = {
            'ip_address': MOCK_IP,
            'country': "🇺🇸 US",
            'asn': "Mock ASN",
            'verdict': "🔴 malicious"
        }
        assert result == expected

@pytest.mark.asyncio
async def test_get_alienvault_info(mock_keys):
    """Тест функции get_alienvault_info."""
    with aioresponses() as m:
        m.get(
            f"{MOCK_URL}{MOCK_IP}/general",
            payload=MOCK_RESPONSE
        )
        m.get(
            f"{MOCK_URL}8.8.8.8/general",
            payload=MOCK_RESPONSE
        )

        ips = [MOCK_IP, "8.8.8.8"]
        success, results = await get_alienvault_info(ips, [])

        assert success is True
        assert len(results) == 2
        for result in results:
            assert result['ip_address'] in ips

@pytest.mark.asyncio
async def test_gen_result():
    """Тест функции gen_result."""
    result = await gen_result(MOCK_RESPONSE)
    expected = {
        'ip_address': MOCK_IP,
        'country': "🇺🇸 US",
        'asn': "Mock ASN",
        'verdict': "🔴 malicious"
    }
    assert result == expected
