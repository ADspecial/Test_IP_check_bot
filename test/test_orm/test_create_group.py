import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from database.orm_query import create_or_update_group_security_host
from database.models import GroupSecurityHost, SecurityHost
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_create_or_update_group_security_host_existing_group(async_session_mock):
    group_mock = GroupSecurityHost(id=1, name="existing_group", description="old_desc", security_hosts=[])
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = group_mock
    async_session_mock.execute.side_effect = [
        execute_mock_1,  # Запрос на получение существующей группы
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[
            SecurityHost(id=10, name="host1", address="1.2.3.4"),
            SecurityHost(id=11, name="host2", address="5.6.7.8")
        ]))))  # Запрос на получение существующих хостов
    ]

    result = await create_or_update_group_security_host(
        async_session_mock,
        name="existing_group",
        description="new_desc",
        security_host_identifiers=["host1", "5.6.7.8"]
    )

    assert result is True
    assert group_mock.description == "new_desc"
    # В группе должно быть 2 хоста
    assert len(group_mock.security_hosts) == 2
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_group_security_host_new_group(async_session_mock):
    # Нет существующей группы
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = None

    # Найдены хосты
    host1 = SecurityHost(id=10, name="host1", address="1.2.3.4")
    host2 = SecurityHost(id=20, name="host2", address="2.3.4.5")
    execute_mock_2 = MagicMock()
    execute_mock_2.scalars.return_value.all.return_value = [host1, host2]

    async_session_mock.execute.side_effect = [
        execute_mock_1,  # группа не найдена
        execute_mock_2   # хосты найдены
    ]

    result = await create_or_update_group_security_host(
        async_session_mock,
        name="new_group",
        description="new_desc",
        security_host_identifiers=["host1", "2.3.4.5"]
    )

    assert result is True
    async_session_mock.add.assert_called_once()  # Добавили новую группу
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_group_security_host_no_hosts(async_session_mock):
    # Существующая группа найдена
    group_mock = GroupSecurityHost(id=2, name="group_empty", description="desc", security_hosts=[])
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = group_mock

    # Не найдено хостов
    execute_mock_2 = MagicMock()
    execute_mock_2.scalars.return_value.all.return_value = []

    async_session_mock.execute.side_effect = [
        execute_mock_1,  # группа найдена
        execute_mock_2   # хостов нет
    ]

    result = await create_or_update_group_security_host(
        async_session_mock,
        name="group_empty",
        description="updated_desc",
        security_host_identifiers=["non_existent_host"]
    )

    assert result is True
    # Описание группы обновлено
    assert group_mock.description == "updated_desc"
    # Хосты не добавлены, так как их нет
    assert len(group_mock.security_hosts) == 0
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_group_security_host_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")

    result = await create_or_update_group_security_host(
        async_session_mock,
        name="error_group",
        description="desc",
        security_host_identifiers=["host1"]
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_group_security_host_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")

    result = await create_or_update_group_security_host(
        async_session_mock,
        name="exception_group",
        description="desc",
        security_host_identifiers=["host1"]
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()
