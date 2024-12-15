import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from database.orm_query import create_or_update_blockrule
from database.models import BlockList, SecurityHost, GroupSecurityHost, Rule
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_create_or_update_blockrule_blocklist_not_found(async_session_mock):
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock_1

    result = await create_or_update_blockrule(
        async_session_mock,
        name="test_rule",
        commit=True,
        blocklist_name="missing_blocklist",
        target="target_host",
        action=False
    )
    assert result is False
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_create_or_update_blockrule_target_not_found(async_session_mock):
    blocklist_mock = BlockList(id=1, name="existing_blocklist")
    # Первый запрос - blocklist
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = blocklist_mock

    # Второй запрос - group_security_host - None
    execute_mock_2 = MagicMock()
    execute_mock_2.scalar_one_or_none.return_value = None

    # Третий запрос - security_host - None
    execute_mock_3 = MagicMock()
    execute_mock_3.scalar_one_or_none.return_value = None

    async_session_mock.execute.side_effect = [
        execute_mock_1,  # blocklist
        execute_mock_2,  # group_security_host
        execute_mock_3   # security_host
    ]

    result = await create_or_update_blockrule(
        async_session_mock,
        name="test_rule",
        commit=True,
        blocklist_name="existing_blocklist",
        target="missing_target",
        action=True
    )
    assert result is False
    async_session_mock.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_create_or_update_blockrule_new_rule(async_session_mock):
    blocklist_mock = BlockList(id=1, name="existing_blocklist")
    security_host_mock = SecurityHost(id=10, name="sec_host", address="1.2.3.4")

    # blocklist found
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = blocklist_mock

    # group_security_host (None)
    execute_mock_2 = MagicMock()
    execute_mock_2.scalar_one_or_none.return_value = None

    # security_host found
    execute_mock_3 = MagicMock()
    execute_mock_3.scalar_one_or_none.return_value = security_host_mock

    # rule not found
    execute_mock_4 = MagicMock()
    execute_mock_4.scalar_one_or_none.return_value = None

    async_session_mock.execute.side_effect = [
        execute_mock_1,  # blocklist
        execute_mock_2,  # group_security_host
        execute_mock_3,  # security_host
        execute_mock_4   # rule
    ]

    result = await create_or_update_blockrule(
        async_session_mock,
        name="new_rule",
        commit=True,
        blocklist_name="existing_blocklist",
        target="sec_host",
        action=False
    )

    assert result is True
    async_session_mock.add.assert_called_once()  # Added new rule
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_blockrule_existing_rule(async_session_mock):
    blocklist_mock = BlockList(id=2, name="blocklist_exists")
    host_mock = SecurityHost(id=20, name="target_host", address="5.6.7.8")
    existing_rule = Rule(id=30, name="existing_rule", commit=False, action=False, blocklists=[], security_hosts=[], group_security_hosts=[])

    # blocklist found
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = blocklist_mock

    # group_security_host (None)
    execute_mock_2 = MagicMock()
    execute_mock_2.scalar_one_or_none.return_value = None

    # security_host found
    execute_mock_3 = MagicMock()
    execute_mock_3.scalar_one_or_none.return_value = host_mock

    # existing rule found
    execute_mock_4 = MagicMock()
    execute_mock_4.scalar_one_or_none.return_value = existing_rule

    async_session_mock.execute.side_effect = [
        execute_mock_1,  # blocklist
        execute_mock_2,  # group_security_host
        execute_mock_3,  # security_host
        execute_mock_4   # rule
    ]

    result = await create_or_update_blockrule(
        async_session_mock,
        name="existing_rule",
        commit=True,
        blocklist_name="blocklist_exists",
        target="target_host",
        action=True
    )

    assert result is True
    # Правило обновилось
    assert existing_rule.commit is True
    assert existing_rule.action is True
    # blocklist и host должны быть добавлены
    assert blocklist_mock in existing_rule.blocklists
    assert host_mock in existing_rule.security_hosts
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_blockrule_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")

    result = await create_or_update_blockrule(
        async_session_mock,
        name="some_rule",
        commit=False,
        blocklist_name="some_blocklist",
        target=None,
        action=False
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_blockrule_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")

    result = await create_or_update_blockrule(
        async_session_mock,
        name="exception_rule",
        commit=False,
        blocklist_name="exception_blocklist",
        target="some_target",
        action=False
    )

    assert result is False
    async_session_mock.rollback.assert_awaited_once()
