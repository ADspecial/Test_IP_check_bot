import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import select
from database.orm_query import delete_rule
from database.models import Rule

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_delete_rule_found(async_session_mock):
    rule_mock = Rule(id=1, name="test_rule")
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = rule_mock
    async_session_mock.execute.return_value = execute_mock

    result = await delete_rule(async_session_mock, "test_rule")
    assert result is True
    async_session_mock.delete.assert_awaited_once_with(rule_mock)
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_rule_not_found(async_session_mock):
    execute_mock = MagicMock()
    execute_mock.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock

    result = await delete_rule(async_session_mock, "non_existent_rule")
    assert result is False
    async_session_mock.delete.assert_not_awaited()
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_delete_rule_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")
    result = await delete_rule(async_session_mock, "error_rule")
    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_delete_rule_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")
    result = await delete_rule(async_session_mock, "exception_rule")
    assert result is False
    # При обычном Exception по коду rollback не вызывается
    async_session_mock.rollback.assert_not_awaited()
