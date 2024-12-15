import sys
sys.path.append('/app')


import pytest
from unittest.mock import patch, MagicMock
from ipcheckers.geo_ip import get_geo_ip, get_geo_response


MOCK_IP = "8.8.8.8"
MOCK_LOCAL_IP = "127.0.0.1"
MOCK_ACCESS_TOKEN = "mock_access_token"
MOCK_COUNTRY_CODE = "US"
MOCK_COUNTRY_NAME = "United States"


@patch("ipinfo.getHandler")
def test_get_geo_ip(mock_get_handler):
    """Тест функции get_geo_ip."""
    mock_handler = MagicMock()
    mock_details = MagicMock()
    mock_details.country = MOCK_COUNTRY_CODE
    mock_details.country_name = MOCK_COUNTRY_NAME
    mock_handler.getDetails.return_value = mock_details
    mock_get_handler.return_value = mock_handler

    with patch("config.config.KEYS", {"GEOIP_KEY": MOCK_ACCESS_TOKEN}):
        result = get_geo_ip(MOCK_IP)

    assert result["country_code"] == MOCK_COUNTRY_CODE
    assert result["country_name"] == MOCK_COUNTRY_NAME


@patch("ipinfo.getHandler")
def test_get_geo_response_valid_ip(mock_get_handler):
    """Тест функции get_geo_response с валидным IP."""
    mock_handler = MagicMock()
    mock_details = MagicMock()
    mock_details.country = MOCK_COUNTRY_CODE
    mock_details.country_name = MOCK_COUNTRY_NAME
    mock_handler.getDetails.return_value = mock_details
    mock_get_handler.return_value = mock_handler

    with patch("config.config.KEYS", {"GEOIP_KEY": MOCK_ACCESS_TOKEN}):
        result = get_geo_response(MOCK_IP)

    assert result == f"🇺🇸 United States"


@patch("ipinfo.getHandler")
def test_get_geo_response_local_ip(mock_get_handler):
    """Тест функции get_geo_response с локальным IP."""
    mock_handler = MagicMock()
    mock_handler.getDetails.side_effect = Exception("Local IP")
    mock_get_handler.return_value = mock_handler

    with patch("config.config.KEYS", {"GEOIP_KEY": MOCK_ACCESS_TOKEN}):
        result = get_geo_response(MOCK_LOCAL_IP)

    assert "bruh, it's looks like a local IP" in result
