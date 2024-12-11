import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from database.orm_query import orm_add_vt_ip
from database.models import Address, Virustotal

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_orm_add_vt_ip_existing_address_existing_vt(async_session_mock):
    address_mock = Address(id=1, ip="1.2.3.4")
    vt_ip_mock = Virustotal(id=10, address=1)
    data = {
        'ip_address': "1.2.3.4",
        'verdict': "malicious",
        'network': "1.2.3.0/24",
        'owner': "Owner",
        'country': "US",
        'rep_score': 5.0,
        'votes': {'harmless': 10, 'malicious': 2},
        'stats': {'count': 42}
    }
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=vt_ip_mock)))),
    ]
    result = await orm_add_vt_ip(async_session_mock, data)
    assert result is True
    assert vt_ip_mock.verdict == data['verdict']
    assert async_session_mock.commit.call_count == 1

@pytest.mark.asyncio
async def test_orm_add_vt_ip_existing_address_no_vt(async_session_mock):
    address_mock = Address(id=2, ip="5.6.7.8")
    data = {
        'ip_address': "5.6.7.8",
        'verdict': "clean",
        'network': "5.6.7.0/24",
        'owner': "Owner2",
        'country': "UK",
        'rep_score': 9.5,
        'votes': {'harmless': 20, 'malicious': 0},
        'stats': {'count': 10}
    }
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=address_mock)))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]
    result = await orm_add_vt_ip(async_session_mock, data)
    assert result is True
    assert async_session_mock.add.call_count == 1
    assert async_session_mock.commit.call_count == 1

@pytest.mark.asyncio
async def test_orm_add_vt_ip_no_address(async_session_mock):
    data = {
        'ip_address': "9.10.11.12",
        'verdict': "unknown",
        'network': "9.10.11.0/24",
        'owner': "Owner3",
        'country': "DE",
        'rep_score': 3.0,
        'votes': {'harmless': 5, 'malicious': 1},
        'stats': {'count': 7}
    }
    async_session_mock.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=None))))
    ]
    result = await orm_add_vt_ip(async_session_mock, data)
    assert result is True
    assert async_session_mock.add.call_count == 2  # Address and Virustotal
    assert async_session_mock.commit.call_count == 2  # One commit for address, one commit for vt

@pytest.mark.asyncio
async def test_orm_add_vt_ip_integrity_error(async_session_mock):
    data = {
        'ip_address': "1.1.1.1",
        'verdict': "clean",
        'network': "1.1.1.0/24",
        'owner': "OwnerX",
        'country': "FR",
        'rep_score': 7.0,
        'votes': {'harmless': 15, 'malicious': 1},
        'stats': {'count': 3}
    }
    async_session_mock.execute.side_effect = IntegrityError("test", "params", "orig")
    result = await orm_add_vt_ip(async_session_mock, data)
    assert result is False
    assert async_session_mock.rollback.call_count == 1

@pytest.mark.asyncio
async def test_orm_add_vt_ip_exception(async_session_mock):
    data = {
        'ip_address': "2.2.2.2",
        'verdict': "clean",
        'network': "2.2.2.0/24",
        'owner': "OwnerY",
        'country': "ES",
        'rep_score': 8.0,
        'votes': {'harmless': 10, 'malicious': 1},
        'stats': {'count': 2}
    }
    async_session_mock.execute.side_effect = Exception("Random error")
    result = await orm_add_vt_ip(async_session_mock, data)
    assert result is False
    assert async_session_mock.rollback.call_count == 1
