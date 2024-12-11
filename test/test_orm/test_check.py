import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from database.orm_query import orm_check_ip_in_table_updated
from database.models import Address, Virustotal

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_address_not_found(async_session_mock):
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]
    result = await orm_check_ip_in_table_updated(async_session_mock, "1.2.3.4", Virustotal)
    assert result is False

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_record_not_found(async_session_mock):
    address_mock = Address(id=1, ip="1.2.3.4")
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]
    result = await orm_check_ip_in_table_updated(async_session_mock, "1.2.3.4", Virustotal)
    assert result is False

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_recently_updated(async_session_mock):
    address_mock = Address(id=2, ip="5.6.7.8")
    record_mock = Virustotal(id=10, address=2)
    record_mock.updated = datetime.utcnow() - timedelta(days=3)
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=record_mock))))
    ]
    result = await orm_check_ip_in_table_updated(async_session_mock, "5.6.7.8", Virustotal)
    assert result is True

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_outdated(async_session_mock):
    address_mock = Address(id=3, ip="9.10.11.12")
    record_mock = Virustotal(id=11, address=3)
    record_mock.updated = datetime.utcnow() - timedelta(days=10)
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=record_mock))))
    ]
    result = await orm_check_ip_in_table_updated(async_session_mock, "9.10.11.12", Virustotal)
    assert result is False

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_no_updated_field(async_session_mock):
    address_mock = Address(id=4, ip="10.10.10.10")
    record_mock = Virustotal(id=12, address=4)
    record_mock.updated = None
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=record_mock))))
    ]
    result = await orm_check_ip_in_table_updated(async_session_mock, "10.10.10.10", Virustotal)
    assert result is False

@pytest.mark.asyncio
async def test_orm_check_ip_in_table_updated_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Test exception")
    result = await orm_check_ip_in_table_updated(async_session_mock, "1.1.1.1", Virustotal)
    assert result is False
