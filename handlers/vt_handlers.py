from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext

from states import Gen

from ipcheckers import virustotal

from handlers import support

import kb
import re
import text


vt_router = Router()

@vt_router.callback_query(F.data == "vt_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.vt_ip)
    await clbck.message.edit_text(text.about_check_ip,reply_markup=kb.back_vt)
    await state.update_data(last_message_id=clbck.message.message_id)

@vt_router.message(Gen.vt_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext):
    await support.handle_last_message_deletion(msg, bot, state)
    await support.process_ip(msg, virustotal.get_vt_info, text.err_ip, text.about_check_ip, kb.back_vt)

# Обработчик команды для проверки ip
@vt_router.message(Command("vt_checkip"))
async def check_ip_command(msg: Message, state: FSMContext):
    await state.set_state(Gen.vt_ip)
    pattern = r'^/vt_checkip (?:(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        await support.process_ip(msg, virustotal.get_vt_info, text.err_ip, None, None)
    else:
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Gen.start)

@vt_router.callback_query(F.data == "vt_file")
async def get_file(clbck: CallbackQuery, state: FSMContext):
    await support.handle_file_request(clbck, state, text.send_text_file, kb.back_vt)

@vt_router.message(Gen.vt_file)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    #await delete_last_two_messages(msg.chat.id, bot)
    await support.process_document(msg, bot, virustotal.get_vt_info, text.err_ip, text.send_text_file, kb.back_vt)

# Обработчик команды для получения файла
@vt_router.message(Command("vt_checkipfile"))
async def command_get_file(msg: Message, state: FSMContext):
    await support.handle_file_request(msg, state, text.send_text_file, kb.back_vt)

@vt_router.message(Gen.vt_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    await support.process_document(msg, bot, virustotal.get_vt_info, text.err_ip, None, None)
