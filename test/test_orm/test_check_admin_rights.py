import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from database.orm_query import check_admin_rights
from database.orm_query import User

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_check_admin_rights_user_found(async_session_mock):
    mock_result = MagicMock()
    mock_result.one_or_none.return_value = (True, False)
    async_session_mock.execute.return_value = mock_result

    result = await check_admin_rights(async_session_mock, 1)
    assert result == (True, False)

@pytest.mark.asyncio
async def test_check_admin_rights_user_found_superadmin(async_session_mock):
    mock_result = MagicMock()
    mock_result.one_or_none.return_value = (True, True)
    async_session_mock.execute.return_value = mock_result

    result = await check_admin_rights(async_session_mock, 2)
    assert result == (True, True)

@pytest.mark.asyncio
async def test_check_admin_rights_user_not_found(async_session_mock):
    mock_result = MagicMock()
    mock_result.one_or_none.return_value = None
    async_session_mock.execute.return_value = mock_result

    result = await check_admin_rights(async_session_mock, 3)
    assert result == (False, False)

@pytest.mark.asyncio
async def test_check_admin_rights_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Test error")

    result = await check_admin_rights(async_session_mock, 4)
    assert result == (False, False)
