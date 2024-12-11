import sys
sys.path.append('/app')

import pytest
import asyncio
from aioresponses import aioresponses

from ipcheckers.ipqualityscore import make_request_ipqs, get_ipqs_info, gen_result  # Замените your_module на ваш путь

# Константы для моков
MOCK_KEY = "mock_ipqs_key"
MOCK_URL_TEMPLATE = "https://www.ipqualityscore.com/api/json/ip/%s/%s?fast=1&strictness=1"
MOCK_IP = "192.168.0.1"
MOCK_RESPONSE = {
    "country_code": "US",
    "host": "mock-host",
    "ISP": "Mock ISP",
    "fraud_score": 85,
    "proxy": False,
    "vpn": True,
    "tor": False,
    "active_vpn": True,
    "last_tor": False,
    "recent_abuse": True,
    "bot_status": False
}

@pytest.fixture
def mock_keys(monkeypatch):
    """Мок для ключей и URL."""
    monkeypatch.setattr('config.config.KEYS', {'IPQS_KEY': MOCK_KEY})
    monkeypatch.setattr('config.config.URLS', {'API_URL_IP_IPQS': MOCK_URL_TEMPLATE})

@pytest.mark.asyncio
async def test_make_request_ipqs(mock_keys):
    """Тест функции make_request_ipqs."""
    with aioresponses() as m:
        # Корректный URL для мока
        base_url = MOCK_URL_TEMPLATE % (MOCK_KEY, MOCK_IP)
        m.get(base_url, payload=MOCK_RESPONSE)

        result = await make_request_ipqs(MOCK_IP)

        expected = {
            'ip_address': MOCK_IP,
            'country': "🇺🇸 US",  # Используется оригинальная функция get_country_flag
            'host': "mock-host",
            'isp': "Mock ISP",
            'verdict': "🟡 suspicious",  # fraud_score = 85
            'fraud_score': 85,
            'proxy': False,
            'vpn': True,
            'tor': False,
            'active_vpn': True,
            'active_tor': False,
            'recent_abuse': True,
            'bot_status': False
        }
        assert result == expected

@pytest.mark.asyncio
async def test_get_ipqs_info(mock_keys):
    """Тест функции get_ipqs_info."""
    with aioresponses() as m:
        # Моки для всех IP-адресов
        url_1 = MOCK_URL_TEMPLATE % (MOCK_KEY, MOCK_IP)
        url_2 = MOCK_URL_TEMPLATE % (MOCK_KEY, "8.8.8.8")
        m.get(url_1, payload=MOCK_RESPONSE)
        m.get(url_2, payload=MOCK_RESPONSE)

        ips = [MOCK_IP, "8.8.8.8"]
        success, results = await get_ipqs_info(ips, [])

        assert success is True
        assert len(results) == len(ips)

        for result in results:
            assert result["ip_address"] in ips
            assert result["verdict"] == "🟡 suspicious"  # fraud_score = 85

@pytest.mark.asyncio
async def test_gen_result():
    """Тест функции gen_result."""
    ip_address = MOCK_IP
    result = await gen_result(ip_address, MOCK_RESPONSE)

    expected = {
        'ip_address': MOCK_IP,
        'country': "🇺🇸 US",  # Используется оригинальная функция get_country_flag
        'host': "mock-host",
        'isp': "Mock ISP",
        'verdict': "🟡 suspicious",  # fraud_score = 85
        'fraud_score': 85,
        'proxy': False,
        'vpn': True,
        'tor': False,
        'active_vpn': True,
        'active_tor': False,
        'recent_abuse': True,
        'bot_status': False
    }
    assert result == expected
