import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from database.orm_query import create_or_update_blocklist
from database.models import BlockList, Address
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_create_or_update_blocklist_new_blocklist(async_session_mock):
    async_session_mock.execute.side_effect = [
        # Первый запрос: нет существующего блоклиста
        MagicMock(scalar_one_or_none=MagicMock(return_value=None)),
        # Второй запрос: нет существующих адресов
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
    ]

    ip_list = ["1.2.3.4", "5.6.7.8"]
    result = await create_or_update_blocklist(
        async_session_mock,
        ip_list,
        name="test_blocklist",
        description="Test description",
        user_id=1
    )

    assert result is True
    # Должны были вызвать commit один раз
    async_session_mock.commit.assert_awaited_once()
    # Был добавлен новый блоклист
    # Было добавлено 2 новых адреса
    assert async_session_mock.add.call_count == 3  # 1 блоклист + 2 адреса

@pytest.mark.asyncio
async def test_create_or_update_blocklist_existing_blocklist(async_session_mock):
    blocklist_mock = BlockList(id=1, name="existing_blocklist", description="Old description", user_id_blocker=2, addresses=[])
    async_session_mock.execute.side_effect = [
        # Первый запрос: блоклист существует
        MagicMock(scalar_one_or_none=MagicMock(return_value=blocklist_mock)),
        # Второй запрос: один адрес уже существует
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[Address(id=10, ip="1.2.3.4")])))),
    ]

    ip_list = ["1.2.3.4", "9.9.9.9"]
    result = await create_or_update_blocklist(
        async_session_mock,
        ip_list,
        name="existing_blocklist",
        description="Updated description",
        user_id=3
    )

    assert result is True
    async_session_mock.commit.assert_awaited_once()
    # Должен был обновиться блоклист, быть добавлен один новый адрес
    assert blocklist_mock.description == "Updated description"
    assert blocklist_mock.user_id_blocker == 3
    # Так как один адрес уже был, добавляем только новый
    # Добавлен должен быть только один новый адрес
    assert async_session_mock.add.call_count == 1  # только новый адрес "9.9.9.9"
    assert len(blocklist_mock.addresses) == 2
    # адрес "1.2.3.4" уже был, новый "9.9.9.9" добавлен

@pytest.mark.asyncio
async def test_create_or_update_blocklist_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("Test DB error")

    ip_list = ["1.2.3.4"]
    result = await create_or_update_blocklist(
        async_session_mock,
        ip_list,
        name="error_blocklist",
        description="Some description",
        user_id=1
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_blocklist_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some unexpected error")

    ip_list = ["1.2.3.4"]
    result = await create_or_update_blocklist(
        async_session_mock,
        ip_list,
        name="unexpected_blocklist",
        description="Some description",
        user_id=1
    )

    assert result is False
    # При обычном Exception rollback не вызывается, только при SQLAlchemyError
    async_session_mock.rollback.assert_not_awaited()
