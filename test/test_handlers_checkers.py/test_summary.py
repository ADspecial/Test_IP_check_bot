import sys
sys.path.append('/app')

import pytest
from unittest.mock import AsyncMock, patch
from aiogram.types import Message, CallbackQuery, Document
from aiogram.fsm.context import FSMContext
from aiogram import Bot
from sqlalchemy.ext.asyncio import AsyncSession
from aiogram.enums import ParseMode

from states import Base_states, Summary_states
import text
import kb

# Импортируем хендлеры, которые мы тестируем
from handlers.summary_handlers import (
    input_about_ip,
    check_ip,
    check_ip_command,
    get_file,
    check_ip_file,
    check_ip_file_command
)

@pytest.mark.asyncio
async def test_input_about_ip():
    state = AsyncMock(spec=FSMContext)
    clbck = AsyncMock(spec=CallbackQuery)
    clbck.data = "summary_ip"
    clbck.message = AsyncMock()
    clbck.message.edit_text = AsyncMock()

    await input_about_ip(clbck, state=state)
    state.set_state.assert_awaited_once_with(Summary_states.check_ip)
    clbck.message.edit_text.assert_awaited_once_with(text.about_check_ip, reply_markup=kb.back_summary)

@pytest.mark.asyncio
@patch("handlers.process.all_checkers", return_value=(True, "summary_report_ok", None))
@patch("handlers.summary_handlers.extract_and_validate", return_value=(["1.2.3.4"], []))
async def test_check_ip_success(mock_extract, mock_all_checkers):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.chat = AsyncMock()
    msg.chat.id = 123
    msg.message_id = 10
    msg.text = "1.2.3.4"

    # Мокаем ответное сообщение
    mesg = AsyncMock(spec=Message)
    mesg.edit_text = AsyncMock()
    mesg.answer = AsyncMock(return_value=AsyncMock(spec=Message))
    msg.answer = AsyncMock(return_value=mesg)

    await check_ip(msg, bot=bot, state=state, session=session)

    bot.delete_message.assert_any_await(123, 9, request_timeout=0)
    bot.delete_message.assert_any_await(123, 10, request_timeout=0)
    msg.answer.assert_awaited_with(text.gen_wait)
    mesg.edit_text.assert_awaited_once_with("summary_report_ok", parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    mesg.answer.assert_awaited_once_with(text.about_check_ip, reply_markup=kb.back_summary)
    mock_all_checkers.assert_awaited_once()

@pytest.mark.asyncio
@patch("handlers.process.all_checkers", return_value=(False, None, ["Virustotal"]))
@patch("handlers.summary_handlers.extract_and_validate", return_value=(["1.2.3.4"], []))
async def test_check_ip_failure(mock_extract, mock_all_checkers):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.chat = AsyncMock()
    msg.chat.id = 123
    msg.message_id = 11

    ans_msg = AsyncMock(spec=Message)
    ans_msg.edit_text = AsyncMock()
    msg.answer = AsyncMock(return_value=ans_msg)
    msg.text = "1.2.3.4"

    await check_ip(msg, bot=bot, state=state, session=session)
    mock_all_checkers.assert_awaited_once()
    ans_msg.edit_text.assert_awaited_once_with(
        text.err_processing.format(service="Virustotal"),
        reply_markup=kb.back_summary
    )

@pytest.mark.asyncio
@patch("handlers.process.all_checkers", return_value=(True, "cmd_report", None))
@patch("handlers.summary_handlers.extract_and_validate", return_value=(["8.8.8.8"], []))
async def test_check_ip_command_success(mock_extract, mock_all_checkers):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.text = "/check 8.8.8.8"
    mesg = AsyncMock(spec=Message)
    mesg.edit_text = AsyncMock()
    msg.answer = AsyncMock(return_value=mesg)

    await check_ip_command(msg, state=state, bot=bot, session=session)

    state.set_state.assert_awaited_with(Base_states.start)
    mesg.edit_text.assert_awaited_once_with("cmd_report", parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    mock_all_checkers.assert_awaited_once()

@pytest.mark.asyncio
async def test_check_ip_command_no_ip():
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.text = "/check"
    msg.chat = AsyncMock()
    msg.chat.id = 456
    msg.message_id = 15
    msg.answer = AsyncMock()

    await check_ip_command(msg, state=state, bot=bot, session=session)
    state.set_state.assert_awaited_with(Base_states.start)
    msg.answer.assert_awaited_with('Не введен ip адрес\n')

@pytest.mark.asyncio
@patch("handlers.process.handle_file_request")
async def test_get_file_callback(mock_handle_file_request):
    state = AsyncMock(spec=FSMContext)
    msg_or_callback = AsyncMock(spec=CallbackQuery)
    msg_or_callback.data = "summary_file"
    await get_file(msg_or_callback, state=state)
    mock_handle_file_request.assert_awaited_once()

@pytest.mark.asyncio
@patch("handlers.process.download_and_read_file", return_value=(["1.1.1.1"], []))
@patch("handlers.process.all_checkers", return_value=(True, "file_report", None))
async def test_check_ip_file_success(mock_all_checkers, mock_download):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.document = AsyncMock(spec=Document)
    msg.document.mime_type = "text/plain"
    msg.chat = AsyncMock()
    msg.chat.id = 789
    msg.message_id = 20

    mesg = AsyncMock(spec=Message)
    mesg.edit_text = AsyncMock()
    mesg.answer = AsyncMock(return_value=AsyncMock(spec=Message))
    msg.answer = AsyncMock(return_value=mesg)

    await check_ip_file(msg, bot=bot, state=state, session=session)
    mesg.edit_text.assert_awaited_once_with("file_report", parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    mesg.answer.assert_awaited_once_with(text.send_text_file, reply_markup=kb.back_summary)
    mock_all_checkers.assert_awaited_once()

@pytest.mark.asyncio
@patch("handlers.process.download_and_read_file", return_value=(["2.2.2.2"], []))
@patch("handlers.process.all_checkers", return_value=(True, "file_report_cmd", None))
async def test_check_ip_file_command_success(mock_all_checkers, mock_download):
    state = AsyncMock(spec=FSMContext)
    bot = AsyncMock(spec=Bot)
    session = AsyncMock()
    msg = AsyncMock(spec=Message)

    msg.document = AsyncMock(spec=Document)
    msg.document.mime_type = "text/plain"
    msg.chat = AsyncMock()
    msg.chat.id = 999
    msg.message_id = 25

    mesg = AsyncMock(spec=Message)
    mesg.edit_text = AsyncMock()
    mesg.answer = AsyncMock(return_value=AsyncMock(spec=Message))
    msg.answer = AsyncMock(return_value=mesg)

    await check_ip_file_command(msg, bot=bot, state=state, session=session)
    mesg.edit_text.assert_awaited_once_with("file_report_cmd", parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    mock_all_checkers.assert_awaited_once()
