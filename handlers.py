from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.exceptions import TelegramBadRequest
from states import Gen
from ipcheckers.virustotal import get_vt_info
from ipcheckers.ipinfo import get_info
from ipcheckers.format import dict_to_string, listdict_to_string
from sqlalchemy.ext.asyncio import AsyncSession
from database.models import History
import kb
import re
import os
import text


router = Router()
message_ids_to_delete = []
#_______________________________________________________________________
#==============================menu=====================================

# Обработчик вывода меню
@router.message(Command("start"))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Gen.start)
    await msg.answer(text.greetings.format(name=msg.from_user.full_name), reply_markup=kb.start_menu)

# Обработчик вывода освновного меню
@router.callback_query(F.data.in_({"start", "view_menu", "Меню", "Выйти в меню", "◀️ Выйти в меню"}))
@router.message(Command("menu"))
async def menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.main_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.menu, reply_markup=kb.start_menu)
        await msg_or_callback.answer('Меню')
    else:
        await msg_or_callback.answer(text.menu, reply_markup=kb.start_menu)

# Обработчик вывода помощи
@router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
@router.message(Command("help"))
async def help_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.help)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.help, reply_markup=kb.iexit_kb)
        await msg_or_callback.answer('Помощь')
    else:
        await msg_or_callback.answer(text.help)

# Обработчик вывода меню проверки IP
@router.callback_query(F.data == "check_menu")
@router.message(Command("check_menu"))
async def check_menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
        await msg_or_callback.answer('Проверка IP')
    else:
        await msg_or_callback.answer(text.check_menu, reply_markup=kb.check_menu)

@router.message(Command("clear"))
async def cmd_clear(message: Message, bot: Bot) -> None:
    try:
        # Все сообщения, начиная с текущего и до первого (message_id = 0)
        for i in range(message.message_id, 0, -1):
            await bot.delete_message(message.from_user.id, i)
    except TelegramBadRequest as ex:
        # Если сообщение не найдено (уже удалено или не существует),
        # код ошибки будет "Bad Request: message to delete not found"
        if ex.message == "Bad Request: message to delete not found":
            print("Все сообщения удалены")
#=======================================================================
#_______________________________________________________________________
#==============================virustotal===============================
# Обработчик вывода меню virustotal
@router.callback_query(F.data == "virustotal_menu")
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

# Обработчик для проверки ip virustotal
@router.callback_query(F.data == "vt_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.vt_ip)
    await clbck.message.edit_text(text.about_check_ip,reply_markup=kb.back_vt)
    await state.update_data(last_message_id=clbck.message.message_id)

@router.message(Gen.vt_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext):
    await handle_last_message_deletion(msg, bot, state)
    await process_ip(msg, get_vt_info, text.err_ip, text.about_check_ip, kb.back_vt)

# Обработчик команды для проверки ip
@router.message(Command("vt_checkip"))
async def check_ip_command(msg: Message, state: FSMContext):
    await state.set_state(Gen.vt_ip)
    pattern = r'^/vt_checkip (?:(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        await process_ip(msg, get_vt_info, text.err_ip, None, None)
    else:
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Gen.start)

@router.callback_query(F.data == "vt_file")
async def get_file(clbck: CallbackQuery, state: FSMContext):
    await handle_file_request(clbck, state, text.send_text_file, kb.back_vt)

@router.message(Gen.vt_file)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    await delete_last_two_messages(msg.chat.id, bot)
    await process_document(msg, bot, get_vt_info, text.err_ip, text.send_text_file, kb.back_vt)

# Обработчик команды для получения файла
@router.message(Command("vt_checkipfile"))
async def command_get_file(msg: Message, state: FSMContext):
    await handle_file_request(msg, state, text.send_text_file, kb.back_vt)

@router.message(Gen.vt_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    await process_document(msg, bot, get_vt_info, text.err_ip, None, None)


#=======================================================================

#_______________________________________________________________________
#==============================ipinfo===================================
# Обработчик вывода меню ipinfo
@router.callback_query(F.data == "ipinfo_menu")
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)

# Обработчик для вывода инфы об ip по ipinfo
@router.callback_query(F.data == "ipi_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipi_ip)
    await clbck.message.edit_text(text.about_check_ip,reply_markup=kb.back_vt)
    await state.update_data(last_message_id=clbck.message.message_id)

@router.message(Gen.ipi_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext):
    await handle_last_message_deletion(msg, bot, state)
    await process_ip(msg, get_info, text.err_ip, text.about_check_ip, kb.back_vt)

#=======================================================================

#_______________________________________________________________________
#======================вспомогательные функции==========================
# Функция обработки ip
async def process_ip(msg: Message, info_function, error_text, post_text, back_kb):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = info_function(ip)
    if not res:
        return await mesg.edit_text(error_text, reply_markup=back_kb)
    if len(res) == 1:
        answer = dict_to_string(res[0])
    else:
        answer = listdict_to_string(res)
    await mesg.edit_text(answer)
    if post_text != None:
        await mesg.answer(post_text, reply_markup=back_kb)

async def handle_file_request(msg_or_callback: Message | CallbackQuery, state: FSMContext, request_text, back_kb):
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_reply_markup()
        await msg_or_callback.message.edit_text(request_text, reply_markup=back_kb)
        await state.set_state(Gen.vt_file)
    else:
        await msg_or_callback.answer(request_text, reply_markup=back_kb)
        await state.set_state(Gen.vt_file_command)

async def process_document(msg: Message, bot: Bot, info_function, error_text, post_text, back_kb):
    if msg.document.mime_type == 'text/plain':
        file_id = msg.document.file_id
        file = await bot.get_file(file_id)

        await bot.download_file(file.file_path, msg.document.file_name)
        with open(msg.document.file_name, 'r', encoding='UTF-8') as file:
            text_file = file.read()
        mesg = await msg.answer(text.gen_wait)
        res = info_function(text_file)
        if not res:
            return await mesg.edit_text(error_text, reply_markup=back_kb)
        await mesg.edit_text(listdict_to_string(res))
        if post_text != None:
            await mesg.answer(post_text, reply_markup=back_kb)
        os.remove(msg.document.file_name)
    else:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)

async def handle_last_message_deletion(msg: Message, bot: Bot, state: FSMContext):
    data = await state.get_data()
    last_message_id = data.get("last_message_id")
    if last_message_id:
        print(last_message_id)
        await bot.delete_message(chat_id=msg.chat.id, message_id=last_message_id)
    await msg.delete()

async def delete_last_two_messages(chat_id: int, bot: Bot):
    messages = await bot.get_chat(chat_id=chat_id)

    for message in messages[:2]:
        try:
            await bot.delete_message(chat_id=chat_id, message_id=message.message_id)
        except Exception as e:
            print(f"Ошибка при удалении сообщения с ID {message.message_id}: {e}")
