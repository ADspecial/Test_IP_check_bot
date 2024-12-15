import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from database.orm_query import get_security_hosts_within_timeframe
from database.models import SecurityHost, GroupSecurityHost, Rule
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_get_security_hosts_within_timeframe_no_filter(async_session_mock):
    group1 = GroupSecurityHost(id=1, name="group1")
    group2 = GroupSecurityHost(id=2, name="group2")
    rule1 = Rule(id=10, name="rule1")
    rule2 = Rule(id=11, name="rule2")
    host_mock = SecurityHost(
        id=1,
        name="test_host",
        description="desc",
        address="1.2.3.4",
        groups=[group1, group2],
        rules=[rule1, rule2]
    )

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [host_mock]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await get_security_hosts_within_timeframe(async_session_mock)
    assert len(result) == 1
    assert result[0]["name"] == "test_host"
    assert result[0]["description"] == "desc"
    assert result[0]["address"] == "1.2.3.4"
    assert "group1" in result[0]["groups"]
    assert "rule1" in result[0]["rules"]

@pytest.mark.asyncio
async def test_get_security_hosts_within_timeframe_with_filter(async_session_mock):
    host_mock_1 = SecurityHost(
        id=2,
        name="host1",
        description="desc1",
        address="5.6.7.8",
        groups=[],
        rules=[]
    )
    host_mock_1.updated = datetime(2023, 6, 1)

    host_mock_2 = SecurityHost(
        id=3,
        name="host2",
        description="desc2",
        address="9.10.11.12",
        groups=[],
        rules=[]
    )
    host_mock_2.updated = datetime(2023, 6, 2)

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [host_mock_1, host_mock_2]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 6, 1)
    end_time = datetime(2023, 6, 3)
    result = await get_security_hosts_within_timeframe(async_session_mock, start_time, end_time)
    assert len(result) == 2
    names = [r["name"] for r in result]
    assert "host1" in names
    assert "host2" in names

@pytest.mark.asyncio
async def test_get_security_hosts_within_timeframe_empty_result(async_session_mock):
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 2)
    result = await get_security_hosts_within_timeframe(async_session_mock, start_time, end_time)
    assert result == []

@pytest.mark.asyncio
async def test_get_security_hosts_within_timeframe_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some error")
    result = await get_security_hosts_within_timeframe(async_session_mock)
    assert result == []
