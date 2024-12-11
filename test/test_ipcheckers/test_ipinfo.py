import sys
sys.path.append('/app')

import pytest
import ipinfo
from unittest.mock import MagicMock
from ipcheckers.ipinfo import get_ipi_info, format_dict  # Замените your_module на ваш путь

# Константы для тестов
MOCK_KEY = "mock_geoip_key"
MOCK_IP = "192.168.0.1"
MOCK_RESPONSE = {
    "ip": MOCK_IP,
    "hostname": "mock-hostname",
    "city": "Mock City",
    "region": "Mock Region",
    "country": "US",
    "loc": "37.7749,-122.4194",
    "org": "Mock Organization",
    "postal": "94103",
    "timezone": "America/Los_Angeles"
}

@pytest.fixture
def mock_ipinfo_handler(monkeypatch):
    """Мок для ipinfo.getHandler."""
    mock_handler = MagicMock()
    mock_handler.getDetails = MagicMock(return_value=MagicMock(all=MOCK_RESPONSE))
    monkeypatch.setattr(ipinfo, "getHandler", lambda key: mock_handler)
    return mock_handler

def test_format_dict():
    """Тест функции format_dict."""
    formatted = format_dict(MOCK_RESPONSE)
    expected = (
        "🌐Ip: 192.168.0.1\n"
        "Hostname: mock-hostname\n"
        "City: Mock City\n"
        "Region: Mock Region\n"
        "Country: US-🇺🇸\n"
        "Org: Mock Organization\n"
        "Postal: 94103\n"
        "Timezone: America/Los_Angeles"
    )
    assert formatted == expected

@pytest.mark.asyncio
async def test_get_ipi_info(mock_ipinfo_handler):
    """Тест функции get_ipi_info."""
    ips = [MOCK_IP, "8.8.8.8"]
    success, results = await get_ipi_info(ips, [])

    # Проверяем успешность
    assert success is True

    # Проверяем количество результатов
    assert len(results) == len(ips)

    # Проверяем содержимое результатов
    for result in results:
        assert result["ip"] in ips
        assert result["country"] == MOCK_RESPONSE["country"]
        assert result["org"] == MOCK_RESPONSE["org"]
