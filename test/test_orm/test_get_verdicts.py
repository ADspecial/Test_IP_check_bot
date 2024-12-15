import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from database.orm_query import get_verdicts_by_ip
from database.models import Address, Virustotal, Ipinfo, Abuseipdb, Kaspersky, CriminalIP, Alienvault, Ipqualityscore

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_get_verdicts_by_ip_all_found(async_session_mock):
    address_mock = Address(id=1, ip="1.2.3.4")

    vt_mock = Virustotal(id=10, address=1, verdict="malicious")
    ipinfo_mock = Ipinfo(id=20, address=1, country="US", region="California", city="San Francisco", org="TestOrg", loc="37.7749,-122.4194")
    abuseipdb_mock = Abuseipdb(id=30, address=1, is_public=True, abuse_confidence_score=50, country="US", isp="TestISP", total_reports=5)
    kaspersky_mock = Kaspersky(id=40, address=1, verdict="safe")
    criminalip_mock = CriminalIP(id=50, address=1, verdict="suspicious")
    alienvault_mock = Alienvault(id=60, address=1, verdict="unknown")
    ipqualityscore_mock = Ipqualityscore(id=70, address=1, verdict="risky")

    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=vt_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=ipinfo_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=abuseipdb_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=kaspersky_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=criminalip_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=alienvault_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=ipqualityscore_mock)))),
    ]

    result = await get_verdicts_by_ip(async_session_mock, "1.2.3.4")
    assert result["virustotal"] == "malicious"
    assert result["ipinfo"]["country"] == "US"
    assert result["abuseipdb"]["abuse_confidence_score"] == 50
    assert result["kaspersky"] == "safe"
    assert result["criminalip"] == "suspicious"
    assert result["alienvault"] == "unknown"
    assert result["ipqualityscore"] == "risky"

@pytest.mark.asyncio
async def test_get_verdicts_by_ip_partial_missing(async_session_mock):
    address_mock = Address(id=2, ip="5.6.7.8")

    vt_mock = Virustotal(id=10, address=2, verdict="clean")
    # Остальные записи отсутствуют
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=vt_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))),
    ]

    result = await get_verdicts_by_ip(async_session_mock, "5.6.7.8")
    assert result["virustotal"] == "clean"
    assert result["ipinfo"]["country"] is None
    assert result["abuseipdb"]["abuse_confidence_score"] is None
    assert result["kaspersky"] is None
    assert result["criminalip"] is None
    assert result["alienvault"] is None
    assert result["ipqualityscore"] is None

@pytest.mark.asyncio
async def test_get_verdicts_by_ip_no_address(async_session_mock):
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]

    result = await get_verdicts_by_ip(async_session_mock, "9.10.11.12")
    assert result == {}

@pytest.mark.asyncio
async def test_get_verdicts_by_ip_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Test error")
    result = await get_verdicts_by_ip(async_session_mock, "1.1.1.1")
    assert result == {}
