import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from database.orm_query import grant_admin_rights
from database.models import User

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_grant_admin_rights_user_found(async_session_mock):
    user_mock = User(id=1, username="test_user", admin_rights=False)
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = user_mock
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await grant_admin_rights(async_session_mock, "test_user")
    assert result is True
    assert user_mock.admin_rights is True
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_grant_admin_rights_user_not_found(async_session_mock):
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = None
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await grant_admin_rights(async_session_mock, "new_user")
    assert result is False
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_grant_admin_rights_integrity_error(async_session_mock):
    async_session_mock.execute.side_effect = IntegrityError("test", "params", "orig")
    result = await grant_admin_rights(async_session_mock, "error_user")
    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_grant_admin_rights_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some error")
    result = await grant_admin_rights(async_session_mock, "exception_user")
    assert result is False
    async_session_mock.rollback.assert_not_awaited()
