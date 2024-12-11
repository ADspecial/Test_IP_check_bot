import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.orm_query import orm_get_data_ip
from  database.models import Address, Virustotal

@pytest.fixture
def async_session_mock():
    """
    Фикстура для мокирования асинхронной сессии.
    """
    session = AsyncMock(spec=AsyncSession)
    return session

@pytest.mark.asyncio
async def test_orm_get_data_ip_found(async_session_mock):
    address_mock = Address(id=1, ip="192.168.0.1")

    virustotal_mock = Virustotal(
        id=1,
        address=address_mock.id,
        verdict="clean",
        network="192.168.0.0/24",
        owner="Test Owner",
        country="US",
        rep_score=10.0,
        votes={"harmless": 5, "malicious": 0},
        stats={"some_stat": 123}
    )

    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=virustotal_mock))))
    ]

    result = await orm_get_data_ip(async_session_mock, Virustotal, "192.168.0.1")

    assert result["verdict"] == "clean"
    assert result["country"] == "US"
    assert result["ip_address"] == "192.168.0.1"
    assert "error" not in result

@pytest.mark.asyncio
async def test_orm_get_data_ip_address_not_found(async_session_mock):
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]

    result = await orm_get_data_ip(async_session_mock, Virustotal, "10.10.10.10")

    assert "error" in result
    assert "not found" in result["error"]

@pytest.mark.asyncio
async def test_orm_get_data_ip_table_record_not_found(async_session_mock):
    address_mock = Address(id=2, ip="8.8.8.8")

    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]

    result = await orm_get_data_ip(async_session_mock, Virustotal, "8.8.8.8")
    assert "error" in result
    assert "not found" in result["error"]
