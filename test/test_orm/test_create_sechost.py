import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from database.orm_query import create_or_update_security_host
from database.models import SecurityHost
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_create_or_update_security_host_existing(async_session_mock):
    host_mock = SecurityHost(
        id=1, name="old_name", description="old_desc", address="1.2.3.4"
    )
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.one_or_none.return_value = host_mock
    execute_mock.scalar_one_or_none.return_value = host_mock
    async_session_mock.execute.return_value = execute_mock

    result = await create_or_update_security_host(
        async_session_mock,
        name="new_name",
        description="new_desc",
        address="1.2.3.4",
        api_token="new_token",
        login="new_login",
        password="new_password"
    )

    assert result is True
    assert host_mock.name == "new_name"
    assert host_mock.description == "new_desc"
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_security_host_new(async_session_mock):
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock

    result = await create_or_update_security_host(
        async_session_mock,
        name="new_name",
        description="new_desc",
        address="5.6.7.8",
        api_token="token",
        login="login",
        password="password"
    )

    assert result is True
    # Был добавлен новый хост
    async_session_mock.add.assert_called_once()
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_security_host_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")
    result = await create_or_update_security_host(
        async_session_mock,
        name="name",
        description="desc",
        address="9.9.9.9",
        api_token="token",
        login="login",
        password="password"
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_security_host_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")
    result = await create_or_update_security_host(
        async_session_mock,
        name="name",
        description="desc",
        address="10.10.10.10",
        api_token="token",
        login="login",
        password="password"
    )

    assert result is False
    # rollback не вызывается при обычном Exception, только при SQLAlchemyError
    async_session_mock.rollback.assert_not_awaited()
