import sys
sys.path.append('/app')

import pytest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from ipcheckers.virustotal import make_request_virustotal, get_vt_info, gen_result, determine_verdict

MOCK_IP = "192.168.1.1"
MOCK_DOMAIN = "example.com"
MOCK_KEY = "mock_virustotal_key"
MOCK_URL_IP_TEMPLATE = "https://mock-vt-api.com/ip/"
MOCK_URL_DOMAIN_TEMPLATE = "https://mock-vt-api.com/domain/"

MOCK_RESPONSE_IP = {
    "data": {
        "id": MOCK_IP,
        "attributes": {
            "network": "192.168.0.0/24",
            "as_owner": "Mock ISP",
            "country": "US",
            "reputation": 10,
            "total_votes": {"malicious": 2, "harmless": 1},
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 2,
                "harmless": 5,
                "undetected": 2,
                "timeout": 0,
            },
        },
    }
}

MOCK_RESPONSE_DOMAIN = {
    "data": {
        "id": MOCK_DOMAIN,
        "attributes": {
            "network": None,
            "as_owner": None,
            "country": "FR",
            "reputation": -5,
            "total_votes": {"malicious": 0, "harmless": 5},
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 5,
                "undetected": 0,
                "timeout": 0,
            },
        },
    }
}

@patch("requests.request")
@patch("config.config.KEYS")
@patch("config.config.URLS")
@pytest.mark.asyncio
async def test_make_request_virustotal_ip(mock_urls, mock_keys, mock_request):
    mock_keys.VT_KEY = MOCK_KEY
    mock_urls.API_URL_IP_VT = MOCK_URL_IP_TEMPLATE
    mock_request.return_value.json.return_value = MOCK_RESPONSE_IP

    result = await make_request_virustotal(MOCK_IP, "ip")
    expected = gen_result(MOCK_RESPONSE_IP)
    assert result == expected

@patch("requests.request")
@patch("config.config.KEYS")
@patch("config.config.URLS")
@pytest.mark.asyncio
async def test_make_request_virustotal_domain(mock_urls, mock_keys, mock_request):
    mock_keys.VT_KEY = MOCK_KEY
    mock_urls.API_URL_DOMAIN_VT = MOCK_URL_DOMAIN_TEMPLATE
    mock_request.return_value.json.return_value = MOCK_RESPONSE_DOMAIN

    result = await make_request_virustotal(MOCK_DOMAIN, "domain")
    expected = gen_result(MOCK_RESPONSE_DOMAIN)
    assert result == expected

@patch("requests.request")
@patch("config.config.KEYS")
@patch("config.config.URLS")
@pytest.mark.asyncio
async def test_get_vt_info(mock_urls, mock_keys, mock_request):
    mock_keys.VT_KEY = MOCK_KEY
    mock_urls.API_URL_IP_VT = MOCK_URL_IP_TEMPLATE
    mock_urls.API_URL_DOMAIN_VT = MOCK_URL_DOMAIN_TEMPLATE

    mock_request.side_effect = [
        MagicMock(json=MagicMock(return_value=MOCK_RESPONSE_IP)),
        MagicMock(json=MagicMock(return_value=MOCK_RESPONSE_DOMAIN)),
    ]

    ips = [MOCK_IP]
    dnss = [MOCK_DOMAIN]
    success, results = await get_vt_info(ips, dnss)

    assert success is True
    assert len(results) == 2
