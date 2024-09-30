from itertools import zip_longest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, ReplyKeyboardMarkup

from database.orm_query import orm_add_file_history, orm_add_vt_ip, orm_check_ip_in_vt, orm_check_ip_in_vt_updated, orm_get_vt_ip

from ipcheckers.format import dict_to_string, format_to_output_dict, listdict_to_string
from ipcheckers.valid_ip import extract_and_validate

from states import Gen

from sqlalchemy.ext.asyncio import AsyncSession

import os

from typing import Callable, List, Dict, Union, Tuple

async def process_db_ip(ips: List[str], dnss: List[str], session: AsyncSession) -> Tuple[List[Dict], List[Dict]]:
    """
    Обработка IP-адресов и DNS, проверка их в базе данных и получение информации.

    Аргументы:
        ips: Список IP-адресов.
        dnss: Список DNS.
        session: Асинхронная сессия для работы с базой данных.

    Возвращает:
        Кортеж из двух списков: первый - данные по IP, второй - данные по DNS.
    """
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

    return db_ips, db_dnss

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
    db_ips, db_dnss = await process_db_ip(ips, dnss, session)

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

async def handle_file_request(
    msg_or_callback: Message | CallbackQuery, state: FSMContext, request_text: str, back_kb: ReplyKeyboardMarkup
) -> None:
    """
    Обработка запроса файла, путем редактирования сообщения или ответа на колбэк, с текстом запроса и установкой состояния Gen.vt_file или Gen.vt_file_command.

    Аргументы:
        msg_or_callback: Сообщение или колбэк, который нужно обработать.
        state: Состояние, которое нужно установить.
        request_text: Текст, запрос файла.
        back_kb: Маркап reply keyboard для использования.
    """
    await (msg_or_callback.message.edit_text if isinstance(msg_or_callback, CallbackQuery) else msg_or_callback.answer)(request_text, reply_markup=back_kb)
    await state.set_state(Gen.vt_file if isinstance(msg_or_callback, CallbackQuery) else Gen.vt_file_command)

async def process_document(
    msg: Message, bot: Bot, info_function: Callable[[List[str], List[str]], List[Dict[str, Union[str, int]]]], session: AsyncSession
) -> Tuple[bool, str]:
    """
    Обработка сообщения, содержащего документ, с извлечением IP-адресов и DNS-имен и обработкой их с помощью указанной функции.

    Аргументы:
        msg: Сообщение, содержащее документ.
        bot: Экземпляр бота.
        info_function: Функция, которую вызывать с извлеченными IP-адресами и DNS-именами.
        session: Сессия базы данных.

    Возвращает:
        Кортеж, где первый элемент - это булево значение, указывающее, была ли функция успешной, а второй элемент - это строка, содержащая результат функции.
    """
    file_id = msg.document.file_id
    file = await bot.get_file(file_id)

    print(msg.from_user.id,msg.document.file_id, msg.chat.id, msg.message_id)

    os.makedirs('data/vt', exist_ok=True)

    increment = 1
    while True:
        file_name = f'data/vt/ip{increment}.txt'
        if not os.path.exists(file_name):
            break
        increment += 1

    await bot.download_file(file.file_path, file_name)
    await orm_add_file_history(session, msg.message_id, file_name)

    with open(file_name, 'r', encoding='UTF-8') as file:
        text_file = file.read()

    ips, dnss = extract_and_validate(text_file)
    if not ips and not dnss:
        os.remove(file_name)
        return False, None

    db_ips, db_dnss = await process_db_ip(ips, dnss, session)

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
