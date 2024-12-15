import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from database.orm_query import get_block_rules_within_timeframe
from database.models import Rule, BlockList, SecurityHost, GroupSecurityHost, RuleFullStatus
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_get_block_rules_within_timeframe_no_filter(async_session_mock):
    blocklist_mock = BlockList(id=1, name="test_blocklist")
    host_mock = SecurityHost(id=2, name="test_host", address="1.2.3.4")
    group_mock = GroupSecurityHost(id=3, name="test_group")
    rule_mock = Rule(
        id=10,
        name="block_rule_1",
        commit=True,
        status="active",
        full=RuleFullStatus.BLOCK,
        blocklists=[blocklist_mock],
        security_hosts=[host_mock],
        group_security_hosts=[group_mock]
    )
    rule_mock.updated = datetime(2023, 1, 1, 12, 0, 0)

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [rule_mock]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await get_block_rules_within_timeframe(async_session_mock)
    assert len(result) == 1
    assert result[0]["name"] == "block_rule_1"
    assert "test_blocklist" in result[0]["blocklists"]
    assert "test_host" in result[0]["security_hosts"]
    assert "test_group" in result[0]["security_hosts"]
    assert result[0]["commit"] is True
    assert result[0]["status"] == "active"
    assert result[0]["updated"] == "2023-01-01 12:00:00"

@pytest.mark.asyncio
async def test_get_block_rules_within_timeframe_with_filter(async_session_mock):
    rule_mock_1 = Rule(
        id=11,
        name="block_rule_2",
        commit=False,
        status=None,
        full=RuleFullStatus.BLOCK,
        blocklists=[],
        security_hosts=[],
        group_security_hosts=[]
    )
    rule_mock_1.updated = datetime(2023, 6, 1, 10, 0, 0)

    rule_mock_2 = Rule(
        id=12,
        name="block_rule_3",
        commit=False,
        status="pending",
        full=RuleFullStatus.BLOCK,
        blocklists=[],
        security_hosts=[],
        group_security_hosts=[]
    )
    rule_mock_2.updated = datetime(2023, 6, 2, 15, 0, 0)

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [rule_mock_1, rule_mock_2]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 6, 1)
    end_time = datetime(2023, 6, 3)
    result = await get_block_rules_within_timeframe(async_session_mock, start_time, end_time)
    assert len(result) == 2
    names = [r["name"] for r in result]
    assert "block_rule_2" in names
    assert "block_rule_3" in names

@pytest.mark.asyncio
async def test_get_block_rules_within_timeframe_empty_result(async_session_mock):
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 2)
    result = await get_block_rules_within_timeframe(async_session_mock, start_time, end_time)
    assert result == []

@pytest.mark.asyncio
async def test_get_block_rules_within_timeframe_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some error")
    result = await get_block_rules_within_timeframe(async_session_mock)
    assert result == []
