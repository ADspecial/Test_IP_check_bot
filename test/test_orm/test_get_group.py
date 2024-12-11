import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from database.orm_query import get_group_security_hosts_within_timeframe
from database.models import GroupSecurityHost, SecurityHost, Rule
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_get_group_security_hosts_within_timeframe_no_filter(async_session_mock):
    host1 = SecurityHost(id=1, name="host1", address="1.2.3.4")
    host2 = SecurityHost(id=2, name="host2", address="5.6.7.8")
    rule1 = Rule(id=10, name="rule1")
    rule2 = Rule(id=11, name="rule2")

    group_mock = GroupSecurityHost(
        id=100,
        name="test_group",
        description="desc",
        security_hosts=[host1, host2],
        rules=[rule1, rule2]
    )

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [group_mock]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await get_group_security_hosts_within_timeframe(async_session_mock)
    assert len(result) == 1
    assert result[0]["name"] == "test_group"
    assert result[0]["description"] == "desc"
    assert "host1" in result[0]["security_hosts"]
    assert "rule1" in result[0]["rules"]

@pytest.mark.asyncio
async def test_get_group_security_hosts_within_timeframe_with_filter(async_session_mock):
    group_mock_1 = GroupSecurityHost(
        id=101,
        name="group1",
        description="desc1",
        security_hosts=[],
        rules=[]
    )
    group_mock_1.updated = datetime(2023, 6, 1)

    group_mock_2 = GroupSecurityHost(
        id=102,
        name="group2",
        description="desc2",
        security_hosts=[],
        rules=[]
    )
    group_mock_2.updated = datetime(2023, 6, 2)

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [group_mock_1, group_mock_2]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 6, 1)
    end_time = datetime(2023, 6, 3)
    result = await get_group_security_hosts_within_timeframe(async_session_mock, start_time, end_time)
    assert len(result) == 2
    names = [r["name"] for r in result]
    assert "group1" in names
    assert "group2" in names

@pytest.mark.asyncio
async def test_get_group_security_hosts_within_timeframe_empty_result(async_session_mock):
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 2)
    result = await get_group_security_hosts_within_timeframe(async_session_mock, start_time, end_time)
    assert result == []

@pytest.mark.asyncio
async def test_get_group_security_hosts_within_timeframe_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some error")
    result = await get_group_security_hosts_within_timeframe(async_session_mock)
    assert result == []
