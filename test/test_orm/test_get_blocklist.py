import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from database.orm_query import get_blocklists_within_timeframe
from database.models import BlockList, User, Address
from sqlalchemy import select

@pytest.fixture
def async_session_mock():
    return AsyncMock(spec=AsyncSession)

@pytest.mark.asyncio
async def test_get_blocklists_within_timeframe_no_filter(async_session_mock):
    user_mock = User(id=1, username="admin")
    blocklist_mock = BlockList(id=10, name="test_blocklist", description="desc", updated=datetime(2023, 1, 1), user=user_mock, addresses=[
        Address(id=100, ip="1.1.1.1"),
        Address(id=101, ip="2.2.2.2")
    ])

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [blocklist_mock]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    result = await get_blocklists_within_timeframe(async_session_mock)
    assert len(result) == 1
    assert result[0]["name"] == "test_blocklist"
    assert result[0]["description"] == "desc"
    assert result[0]["username"] == "admin"
    assert result[0]["addresses"] == ["1.1.1.1", "2.2.2.2"]

@pytest.mark.asyncio
async def test_get_blocklists_within_timeframe_with_filter(async_session_mock):
    user_mock = User(id=2, username="user2")
    blocklist_mock_1 = BlockList(id=20, name="bl1", description="desc1", updated=datetime(2023, 6, 1), user=user_mock, addresses=[])
    blocklist_mock_2 = BlockList(id=21, name="bl2", description="desc2", updated=datetime(2023, 6, 2), user=user_mock, addresses=[])

    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = [blocklist_mock_1, blocklist_mock_2]
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 6, 1)
    end_time = datetime(2023, 6, 3)
    result = await get_blocklists_within_timeframe(async_session_mock, start_time, end_time)
    assert len(result) == 2
    names = [r["name"] for r in result]
    assert "bl1" in names
    assert "bl2" in names

@pytest.mark.asyncio
async def test_get_blocklists_within_timeframe_empty_result(async_session_mock):
    execute_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    execute_mock.scalars.return_value = scalars_mock
    async_session_mock.execute.return_value = execute_mock

    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 2)
    result = await get_blocklists_within_timeframe(async_session_mock, start_time, end_time)
    assert result == []

@pytest.mark.asyncio
async def test_get_blocklists_within_timeframe_exception(async_session_mock):
    async_session_mock.execute.side_effect = Exception("Some error")
    result = await get_blocklists_within_timeframe(async_session_mock)
    assert result == []
