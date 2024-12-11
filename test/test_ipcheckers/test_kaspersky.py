import sys
sys.path.append('/app')

import os
import pytest
from unittest.mock import patch
from dotenv import load_dotenv
from ipcheckers.kaspersky import (
    make_request_kaspersky,
    get_kaspersky_info,
    gen_result_ip,
    gen_result_domain,
    determine_verdict_kaspersky,
)

# Загрузка .env файла
load_dotenv()

# Константы для тестов
MOCK_URL_IP_TEMPLATE = "https://opentip.kaspersky.com/api/v1/search/ip?request="
MOCK_URL_DOMAIN_TEMPLATE = "https://opentip.kaspersky.com/api/v1/search/domain?request="
MOCK_IP = "192.168.0.1"
MOCK_DOMAIN = "example.com"
MOCK_IP_RESPONSE = {
    "IpGeneralInfo": {
        "Ip": MOCK_IP,
        "Status": "Active",
        "CountryCode": "US"
    },
    "IpWhoIs": {
        "Net": {
            "Name": "MockNet"
        }
    },
    "Zone": "Red"
}
MOCK_DOMAIN_RESPONSE = {
    "DomainWhoIsInfo": {
        "DomainName": MOCK_DOMAIN
    },
    "Zone": "Orange"
}


@pytest.fixture
def mock_keys(monkeypatch):
    """Мок для ключей."""
    monkeypatch.setenv('API_KASPERSKY_KEY', os.getenv('API_KASPERSKY_KEY'))


@patch('requests.request')
@pytest.mark.asyncio
async def test_make_request_kaspersky_ip(mock_request, mock_keys):
    """Тест функции make_request_kaspersky для IP."""
    mock_request.return_value.json.return_value = MOCK_IP_RESPONSE

    result = await make_request_kaspersky(MOCK_IP, 'ip')

    expected = {
        'ip_address': MOCK_IP,
        'status': 'Active',
        'country': '🇺🇸 US',
        'net_name': 'MockNet',
        'verdict': '🔴 malicious',
    }
    assert result == expected
    mock_request.assert_called_once_with(
        method='GET',
        url=f"{MOCK_URL_IP_TEMPLATE}{MOCK_IP}",
        headers={'x-api-key': os.getenv('API_KASPERSKY_KEY')}
    )


@patch('requests.request')
@pytest.mark.asyncio
async def test_make_request_kaspersky_domain(mock_request, mock_keys):
    """Тест функции make_request_kaspersky для домена."""
    mock_request.return_value.json.return_value = MOCK_DOMAIN_RESPONSE

    result = await make_request_kaspersky(MOCK_DOMAIN, 'domain')

    expected = {
        'ip_address': MOCK_DOMAIN,
        'status': None,
        'country': None,
        'net_name': None,
        'verdict': '🟡 suspicious',
    }
    assert result == expected
    mock_request.assert_called_once_with(
        method='GET',
        url=f"{MOCK_URL_DOMAIN_TEMPLATE}{MOCK_DOMAIN}",
        headers={'x-api-key': os.getenv('API_KASPERSKY_KEY')}
    )


@patch('requests.request')
@pytest.mark.asyncio
async def test_get_kaspersky_info(mock_request, mock_keys):
    """Тест функции get_kaspersky_info."""
    mock_request.side_effect = [
        type('MockResponse', (), {'json': lambda: MOCK_IP_RESPONSE}),
        type('MockResponse', (), {'json': lambda: MOCK_DOMAIN_RESPONSE}),
    ]

    ips = [MOCK_IP]
    dnss = [MOCK_DOMAIN]

    success, results = await get_kaspersky_info(ips, dnss)

    assert success is True
    assert len(results) == 2
    assert results[0] == {
        'ip_address': MOCK_IP,
        'status': 'Active',
        'country': '🇺🇸 US',
        'net_name': 'MockNet',
        'verdict': '🔴 malicious',
    }
    assert results[1] == {
        'ip_address': MOCK_DOMAIN,
        'status': None,
        'country': None,
        'net_name': None,
        'verdict': '🟡 suspicious',
    }


def test_gen_result_ip():
    """Тест функции gen_result_ip."""
    result = gen_result_ip(MOCK_IP_RESPONSE)
    expected = {
        'ip_address': MOCK_IP,
        'status': 'Active',
        'country': '🇺🇸 US',
        'net_name': 'MockNet',
        'verdict': '🔴 malicious',
    }
    assert result == expected


def test_gen_result_domain():
    """Тест функции gen_result_domain."""
    result = gen_result_domain(MOCK_DOMAIN_RESPONSE)
    expected = {
        'ip_address': MOCK_DOMAIN,
        'status': None,
        'country': None,
        'net_name': None,
        'verdict': '🟡 suspicious',
    }
    assert result == expected


def test_determine_verdict_kaspersky():
    """Тест функции determine_verdict_kaspersky."""
    assert determine_verdict_kaspersky("Red") == "🔴 malicious"
    assert determine_verdict_kaspersky("Orange") == "🟡 suspicious"
    assert determine_verdict_kaspersky("Yellow") == "🟡 suspicious"
    assert determine_verdict_kaspersky("Grey") == "⚫️ undetected"
    assert determine_verdict_kaspersky("Unknown") == "🟢 harmless"
