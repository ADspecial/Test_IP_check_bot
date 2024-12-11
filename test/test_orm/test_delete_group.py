import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import select
from database.orm_query import delete_group_security_host
from database.models import GroupSecurityHost

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_delete_group_security_host_found(async_session_mock):
    group_mock = GroupSecurityHost(id=1, name="test_group")
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = group_mock
    async_session_mock.execute.return_value = execute_mock

    result = await delete_group_security_host(async_session_mock, "test_group")
    assert result is True
    async_session_mock.delete.assert_awaited_once_with(group_mock)
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_group_security_host_not_found(async_session_mock):
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock

    result = await delete_group_security_host(async_session_mock, "non_existent_group")
    assert result is False
    async_session_mock.delete.assert_not_awaited()
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_delete_group_security_host_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")
    result = await delete_group_security_host(async_session_mock, "error_group")
    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_group_security_host_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")
    result = await delete_group_security_host(async_session_mock, "exception_group")
    assert result is False
    async_session_mock.rollback.assert_not_awaited()
