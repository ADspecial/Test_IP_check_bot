import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import select
from database.orm_query import delete_security_host
from database.models import SecurityHost

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_delete_security_host_by_address_found(async_session_mock):
    host_mock = SecurityHost(id=1, name="test_host", address="1.2.3.4")
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = host_mock
    async_session_mock.execute.return_value = execute_mock

    result = await delete_security_host(async_session_mock, "1.2.3.4")
    assert result is True
    async_session_mock.delete.assert_awaited_once_with(host_mock)
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_security_host_by_name_found(async_session_mock):
    host_mock = SecurityHost(id=2, name="test_host_2", address="5.6.7.8")
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = host_mock
    async_session_mock.execute.return_value = execute_mock

    result = await delete_security_host(async_session_mock, "test_host_2")
    assert result is True
    async_session_mock.delete.assert_awaited_once_with(host_mock)
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_security_host_not_found(async_session_mock):
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock

    result = await delete_security_host(async_session_mock, "non_existent")
    assert result is False
    async_session_mock.delete.assert_not_awaited()
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_delete_security_host_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")
    result = await delete_security_host(async_session_mock, "error_host")
    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_security_host_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")
    result = await delete_security_host(async_session_mock, "exception_host")
    assert result is False
    async_session_mock.rollback.assert_not_awaited()
