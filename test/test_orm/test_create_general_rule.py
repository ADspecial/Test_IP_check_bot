import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from database.orm_query import create_or_update_general_rule, parse_ip_port
from database.models import Rule
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

def test_parse_ip_port_with_port():
    ip, port = parse_ip_port("192.168.1.1:22")
    assert ip == ["192.168.1.1"]
    assert port == [22]

def test_parse_ip_port_without_port():
    ip, port = parse_ip_port("BlockListName")
    assert ip == ["BlockListName"]
    assert port == []

@pytest.mark.asyncio
async def test_create_or_update_general_rule_new(async_session_mock):
    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = None
    async_session_mock.execute.return_value = execute_mock_1

    result = await create_or_update_general_rule(
        async_session_mock,
        name="new_rule",
        source="10.0.0.1:80",
        destination="10.0.0.2:443",
        protocol="TCP",
        action=True,
        commit=True
    )

    assert result is True
    async_session_mock.add.assert_called_once()
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_general_rule_existing(async_session_mock):
    existing_rule = Rule(
        id=1, name="existing_rule", commit=False, action=False,
        source_ip=[], source_port=[], destination_ip=[], destination_port=[], protocol=[]
    )

    execute_mock_1 = MagicMock()
    execute_mock_1.scalar_one_or_none.return_value = existing_rule
    async_session_mock.execute.return_value = execute_mock_1

    result = await create_or_update_general_rule(
        async_session_mock,
        name="existing_rule",
        source="192.168.1.1:22",
        destination="192.168.1.2:80",
        protocol="TCP/UDP",
        action=False,
        commit=False
    )

    assert result is True
    # Check that existing rule updated
    assert existing_rule.source_ip == ["192.168.1.1"]
    assert existing_rule.source_port == [22]
    assert existing_rule.destination_ip == ["192.168.1.2"]
    assert existing_rule.destination_port == [80]
    # TCP/UDP -> ["TCP", "UDP"]
    assert existing_rule.protocol == ["TCP", "UDP"]
    assert existing_rule.action is False
    assert existing_rule.commit is False
    async_session_mock.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_general_rule_sqlalchemy_error(async_session_mock):
    async_session_mock.execute.side_effect = SQLAlchemyError("DB error")
    result = await create_or_update_general_rule(
        async_session_mock,
        name="error_rule",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        action=True,
        commit=True
    )
    assert result is False
    async_session_mock.rollback.assert_awaited_once()

@pytest.mark.asyncio
async def test_create_or_update_general_rule_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Unexpected error")
    result = await create_or_update_general_rule(
        async_session_mock,
        name="exception_rule",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol="TCP",
        action=True,
        commit=True
    )
    assert result is False
    async_session_mock.rollback.assert_not_awaited()
