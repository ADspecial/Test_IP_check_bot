from itertools import zip_longest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, ReplyKeyboardMarkup

from database.models import Ipinfo, Virustotal, Abuseipdb, Kaspersky, CriminalIP, Alienvault, Ipqualityscore
from database import orm_query

from ipcheckers import format
from ipcheckers.valid_ip import extract_and_validate

from states import VT_states, IPI_states, ADB_states, KSP_states, CIP_states, ALV_states, IPQS_states

from sqlalchemy.ext.asyncio import AsyncSession

import os

from typing import Callable, List, Dict, Union, Tuple

STATE_TABLE_MAP = {
    VT_states.check_ip: (Virustotal, format.format_to_output_dict_vt),
    IPI_states.check_ip: (Ipinfo, format.format_to_output_dict_ipi),
    ADB_states.check_ip: (Abuseipdb, format.format_to_output_dict_adb),
    KSP_states.check_ip: (Kaspersky, format.format_to_output_dict_ksp),
    CIP_states.check_ip: (CriminalIP, format.format_to_output_dict_cip),
    ALV_states.check_ip: (Alienvault, format.format_to_output_dict_alv),
    IPQS_states.check_ip: (Ipqualityscore, format.format_to_output_dict_ipqs),
    VT_states.check_ip_file: (Virustotal, format.format_to_output_dict_vt),
    IPI_states.check_ip_file: (Ipinfo, format.format_to_output_dict_ipi),
    ADB_states.check_ip_file: (Abuseipdb, format.format_to_output_dict_adb),
    KSP_states.check_ip_file: (Kaspersky, format.format_to_output_dict_ksp),
    CIP_states.check_ip_file: (CriminalIP, format.format_to_output_dict_cip),
    ALV_states.check_ip_file: (Alienvault, format.format_to_output_dict_alv),
    IPQS_states.check_ip_file: (Ipqualityscore, format.format_to_output_dict_ipqs),
    VT_states.check_ip_file_command: (Virustotal, format.format_to_output_dict_vt),
    IPI_states.check_ip_file_command: (Ipinfo, format.format_to_output_dict_ipi),
    ADB_states.check_ip_file_command: (Abuseipdb, format.format_to_output_dict_adb),
    KSP_states.check_ip_file_command: (Kaspersky, format.format_to_output_dict_ksp),
    CIP_states.check_ip_file_command: (CriminalIP, format.format_to_output_dict_cip),
    ALV_states.check_ip_file_command: (Alienvault, format.format_to_output_dict_alv),
    IPQS_states.check_ip_file_command: (Ipqualityscore, format.format_to_output_dict_ipqs),
}

STATE_FILE_MAP = {

    VT_states.check_ip_file: ('virustotal', Virustotal),
    IPI_states.check_ip_file: ('ipinfo', Ipinfo),
    ADB_states.check_ip_file: ('abuseipdb', Abuseipdb),
    KSP_states.check_ip_file: ('kaspersky', Kaspersky),
    CIP_states.check_ip_file: ('criminalip', CriminalIP),
    ALV_states.check_ip_file: ('alienvault', Alienvault),
    IPQS_states.check_ip_file: ('ipqualityscore',Ipqualityscore),
    VT_states.check_ip_file_command: ('virustotal', Virustotal),
    IPI_states.check_ip_file_command: ('ipinfo', Ipinfo),
    ADB_states.check_ip_file_command: ('abuseipdb', Abuseipdb),
    KSP_states.check_ip_file_command: ('kaspersky', Kaspersky),
    CIP_states.check_ip_file_command: ('criminalip', CriminalIP),
    ALV_states.check_ip_file_command: ('alienvault', Alienvault),
    IPQS_states.check_ip_file_command: ('ipqualityscore', Ipqualityscore),
}

async def process_db_ip(ips: List[str], dnss: List[str], session: AsyncSession, table_model) -> Tuple[List[Dict], List[Dict]]:
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
        if ip and await orm_query.orm_check_ip_in_table(session, ip, table_model = table_model):
            if await orm_query.orm_check_ip_in_table_updated(session, ip, table_model):
                ips.remove(ip)
                db_ips.append(await orm_query.orm_get_data_ip(session, table_model, ip))

        if dns and await orm_query.orm_check_ip_in_table(session, dns, table_model) and table_model == Virustotal:
            if await orm_query.orm_check_ip_in_table_updated(session, dns, table_model):
                dnss.remove(dns)
                db_dnss.append(await orm_query.orm_get_data_ip(session, table_model, ip))

    return db_ips, db_dnss

async def process_ip(msg: Message, info_function: Callable[[str], List[Dict[str, Union[str, int]]]], db_function, state: FSMContext, session: AsyncSession) -> Tuple[bool, str]:
    """
    Обработка сообщения, содержащего IP-адрес.

    Аргументы:
        msg: Сообщение, содержащее IP-адрес.
        info_function: Функция, которая принимает IP-адрес и возвращает список словарей, содержащих информацию об IP.

    Возвращает:
        Кортеж, где первый элемент - это булево значение, указывающее, была ли функция успешной, а второй элемент - это строка, содержащая результат функции.
    """
    current_state = await state.get_state()

    table_name, format_func = STATE_TABLE_MAP.get(current_state)

    ips, dnss = extract_and_validate(msg.text)
    if not ips and not dnss: return False, None
    db_ips, db_dnss = await process_db_ip(ips, dnss, session, table_name)
    reports = []
    if ips or dnss: result, reports = await info_function(ips, dnss)

    combined_reports = db_ips + db_dnss + reports

    if not combined_reports: return False, None

    for report in reports:
        await db_function(session, report)

    format_reports = [format_func(report) for report in combined_reports]
    answer = format.listdict_to_string(format_reports)
    return True, answer


async def handle_file_request(
    msg_or_callback: Message | CallbackQuery, state: FSMContext, request_text: str, back_kb: ReplyKeyboardMarkup, gen_state_inline, gen_state_command
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
    await state.set_state(gen_state_inline if isinstance(msg_or_callback, CallbackQuery) else gen_state_command)

async def process_document(
    msg: Message, bot: Bot, info_function: Callable[[List[str], List[str]], List[Dict[str, Union[str, int]]]], db_function, state: FSMContext, session: AsyncSession
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
    current_state = await state.get_state()
    dir_name, table_name = STATE_FILE_MAP.get(current_state)

    os.makedirs(f'data/{dir_name}', exist_ok=True)
    file_id = msg.document.file_id
    file = await bot.get_file(file_id)


    file_name = next(f'data/{dir_name}/ip{num}.txt' for num in range(1, 1000) if not os.path.exists(f'data/{dir_name}/ip{num}.txt'))

    await bot.download_file(file.file_path, file_name)
    await orm_query.orm_add_file_history(session, msg.message_id, file_name)

    with open(file_name, 'r', encoding='UTF-8') as file:
        text_file = file.read()

    ips, dnss = extract_and_validate(text_file)
    if not ips and not dnss:
        os.remove(file_name)
        return False, None

    db_ips, db_dnss = await process_db_ip(ips, dnss, session, table_name)
    result, reports = await info_function(ips, dnss)

    combined_reports  = db_ips + db_dnss + reports
    if not combined_reports :
        return False, None

    for report in reports:
        await db_function(session, report)

    table_name,format_func = STATE_TABLE_MAP.get(current_state)
    format_reports = [format_func(report) for report in combined_reports]
    answer = format.listdict_to_string(format_reports)
    return True, answer
