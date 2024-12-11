import sys
sys.path.append('/app')

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram import Bot

from handlers.vt_handlers import input_about_ip, check_single_ip
from states import VT_states, Base_states
import text
import kb

@pytest.mark.asyncio
async def test_input_about_ip():
    state = AsyncMock(spec=FSMContext)
    clbck = AsyncMock(spec=CallbackQuery)
    clbck.data = "vt_ip"
    clbck.message = AsyncMock()
    clbck.message.edit_text = AsyncMock()

    await input_about_ip(clbck, state=state)

    state.set_state.assert_awaited_once_with(VT_states.check_ip)
    clbck.message.edit_text.assert_awaited_once_with(text.about_check_ip, reply_markup=kb.back_vt)


@pytest.mark.asyncio
@patch("handlers.process.process_ip", return_value=(True, "some_report"))
async def test_check_single_ip_success(mock_process_ip):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()

    msg = AsyncMock(spec=Message)
    msg.chat = AsyncMock()
    msg.chat.id = 456
    msg.message_id = 123
    msg.answer = AsyncMock()

    await check_single_ip(msg, bot=bot, state=state, session=session)

    bot.delete_message.assert_any_await(456, 122, request_timeout=0)
    bot.delete_message.assert_any_await(456, 123, request_timeout=0)
    msg.answer.assert_awaited_with(text.gen_wait)
    mock_process_ip.assert_awaited_once()


@pytest.mark.asyncio
@patch("handlers.process.process_ip", return_value=(False, "error_report"))
async def test_check_single_ip_failure(mock_process_ip):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()

    msg = AsyncMock(spec=Message)
    msg.chat = AsyncMock()
    msg.chat.id = 456
    msg.message_id = 200
    answer_msg = AsyncMock(spec=Message)
    answer_msg.edit_text = AsyncMock()
    msg.answer = AsyncMock(return_value=answer_msg)

    await check_single_ip(msg, bot=bot, state=state, session=session)

    bot.delete_message.assert_any_await(456, 199, request_timeout=0)
    bot.delete_message.assert_any_await(456, 200, request_timeout=0)
    msg.answer.assert_awaited_with(text.gen_wait)
    answer_msg.edit_text.assert_awaited_once_with(text.err_ip, reply_markup=kb.back_vt)
    mock_process_ip.assert_awaited_once()
