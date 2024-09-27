from itertools import zip_longest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from database.orm_query import orm_add_vt_ip, orm_check_ip_in_vt, orm_check_ip_in_vt_updated, orm_get_vt_ip

from ipcheckers.format import dict_to_string, format_to_output_dict, listdict_to_string
from ipcheckers.valid_ip import extract_and_validate

from states import Gen

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import os
import text

from typing import Callable, List, Dict, Union, Tuple

async def process_ip(msg: Message, info_function: Callable[[str], List[Dict[str, Union[str, int]]]], session: AsyncSession) -> Tuple[bool, str]:
    """
    Обработка сообщения, содержащего IP-адрес.

    Аргументы:
        msg: Сообщение, содержащее IP-адрес.
        info_function: Функция, которая принимает IP-адрес и возвращает список словарей, содержащих информацию об IP.

    Возвращает:
        Кортеж, где первый элемент - это булево значение, указывающее, была ли функция успешной, а второй элемент - это строка, содержащая результат функции.
    """

    ips, dnss = extract_and_validate(msg.text)
    if not ips and not dnss: return False, None
    db_ips = []
    db_dnss = []

    for ip, dns in zip_longest(ips[:], dnss[:]):
        if ip and await orm_check_ip_in_vt(session, ip):
            if await orm_check_ip_in_vt_updated(session, ip):
                ips.remove(ip)
                data_ip = await orm_get_vt_ip(session, ip)
                db_ips.append(data_ip)
        if dns and await orm_check_ip_in_vt(session, dns):
            if await orm_check_ip_in_vt_updated(session, dns):
                dnss.remove(dns)
                data_dns = await orm_get_vt_ip(session, dns)
                db_dnss.append(data_dns)

    results = await info_function(ips, dnss)

    combined_results = db_ips + db_dnss + results

    if not combined_results: return False, None

    for result in results:
        await orm_add_vt_ip(session, result)

    if len(combined_results) > 1:
        answer = listdict_to_string(combined_results)
    else:
        format_dict = format_to_output_dict(combined_results[0])
        answer = dict_to_string(format_dict)
    return True, answer

async def handle_file_request(msg_or_callback: Message | CallbackQuery, state: FSMContext, request_text, back_kb):
    await (msg_or_callback.message.edit_text if isinstance(msg_or_callback, CallbackQuery) else msg_or_callback.answer)(request_text, reply_markup=back_kb)
    await state.set_state(Gen.vt_file if isinstance(msg_or_callback, CallbackQuery) else Gen.vt_file_command)

async def process_document(msg: Message, bot: Bot, state: FSMContext, info_function, error_text, post_text, back_kb):
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
        return

    file_id = msg.document.file_id
    file = await bot.get_file(file_id)

    os.makedirs('data/vt', exist_ok=True)

    increment = 1
    while True:
        file_name = f'data/vt/ip{increment}.txt'
        if not os.path.exists(file_name):
            break
        increment += 1

    await bot.download_file(file.file_path, file_name)

    with open(file_name, 'r', encoding='UTF-8') as file:
        text_file = file.read()

    mesg = await msg.answer(text.gen_wait)
    res = info_function(text_file)
    if not res:
        await mesg.edit_text(error_text, reply_markup=back_kb)
        os.remove(file_name)
    else:
        await mesg.edit_text(listdict_to_string(res))
        if post_text:
            await mesg.answer(post_text, reply_markup=back_kb)
            await state.update_data(last_message_id=mesg.message_id)

async def handle_last_message_deletion(msg: Message, bot: Bot, state: FSMContext):
    data = await state.get_data()
    last_message_id = data.get("last_message_id")
    if last_message_id:
        await bot.delete_message(chat_id=msg.chat.id, message_id=last_message_id, request_timeout=0)
    await msg.delete(request_timeout=0)

async def delete_last_two_messages(chat_id: int, bot: Bot):
    messages = await bot.get_chat_history(chat_id=chat_id, limit=2)

    for message in messages:
        await bot.delete_message(chat_id=chat_id, message_id=message.message_id)
