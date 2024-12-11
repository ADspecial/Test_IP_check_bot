import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from database.orm_query import delete_blocklist_by_name
from database.models import BlockList, blocklist_address_association

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_delete_blocklist_by_name_found(async_session_mock):
    blocklist_mock = BlockList(id=1, name="test_blocklist")
    # Первый запрос возвращает найденный блоклист
    execute_mock1 = MagicMock()
    execute_mock1.scalar_one_or_none.return_value = blocklist_mock

    async_session_mock.execute.side_effect = [
        execute_mock1, # Запрос на проверку существования блоклиста
        MagicMock(),   # Запрос на удаление связей
        MagicMock()    # Запрос на удаление самого блоклиста
    ]

    result = await delete_blocklist_by_name(async_session_mock, "test_blocklist")
    assert result is True
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_blocklist_by_name_not_found(async_session_mock):
    execute_mock1 = MagicMock()
    execute_mock1.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock1

    result = await delete_blocklist_by_name(async_session_mock, "non_existent_blocklist")
    assert result is False
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_delete_blocklist_by_name_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Test error")
    result = await delete_blocklist_by_name(async_session_mock, "error_blocklist")
    assert result is False
    async_session_mock.rollback.assert_awaited_once()
