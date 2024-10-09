from itertools import zip_longest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, ReplyKeyboardMarkup

from database.models import Ipi_ip, Vt_ip, Abuseipdb, Kaspersky, CriminalIP, Alienvault
from database import orm_query

from ipcheckers import format
from ipcheckers.valid_ip import extract_and_validate

from states import VT_states, IPI_states, ADB_states, KSP_states, CIP_states, ALV_states

from sqlalchemy.ext.asyncio import AsyncSession

import os

from typing import Callable, List, Dict, Union, Tuple
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

    orm_func = {
        Vt_ip: orm_query.orm_check_ip_in_vt,
        Ipi_ip: orm_query.orm_get_ipi_ip_data,
        Abuseipdb: orm_query.orm_get_abuseipdb_data,
        Kaspersky: orm_query.orm_get_kaspersky_data,
        CriminalIP: orm_query.orm_get_criminalip_data,
        Alienvault: orm_query.orm_get_alienvault_data,
    }[table_model]

    for ip, dns in zip_longest(ips[:], dnss[:]):
        if ip and await orm_query.orm_check_ip_in_table(session, ip, table_model = table_model):
            if await orm_query.orm_check_ip_in_table_updated(session, ip, table_model):
                ips.remove(ip)
                data_ip = await orm_func(session,ip)
                db_ips.append(data_ip)

        if dns and await orm_query.orm_check_ip_in_table(session, dns, table_model) and table_model == Vt_ip:
            if await orm_query.orm_check_ip_in_table_updated(session, dns, table_model):
                dnss.remove(dns)
                data_dns = await orm_query.orm_get_vt_ip(session, dns)
                db_dnss.append(data_dns)

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

    table_name = {VT_states.check_ip: Vt_ip, IPI_states.check_ip: Ipi_ip, ADB_states.check_ip: Abuseipdb, KSP_states.check_ip: Kaspersky, CIP_states.check_ip: CriminalIP, ALV_states.check_ip: Alienvault}[current_state]

    ips, dnss = extract_and_validate(msg.text)
    if not ips and not dnss: return False, None
    db_ips, db_dnss = await process_db_ip(ips, dnss, session, table_name)
    reports = []
    if ips or dnss: result, reports = await info_function(ips, dnss)

    combined_reports = db_ips + db_dnss + reports

    if not combined_reports: return False, None

    for report in reports:
        await db_function(session, report)

    if current_state == VT_states.check_ip:
        if len(combined_reports) > 1:
            answer = format.listdict_to_string_vt(combined_reports)
        else:
            format_dict = format.format_to_output_dict_vt(combined_reports[0])
            answer = format.dict_to_string(format_dict)

    format_dict_func = {
        IPI_states.check_ip: format.format_to_output_dict_ipi,
        ADB_states.check_ip: format.format_to_output_dict_adb,
        KSP_states.check_ip: format.format_to_output_dict_ksp,
        CIP_states.check_ip: format.format_to_output_dict_cip,
        ALV_states.check_ip: format.format_to_output_dict_alv,
    }
    format_reports = [format_dict_func[current_state](report) for report in combined_reports]
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
    file_id = msg.document.file_id
    file = await bot.get_file(file_id)


    print(msg.from_user.id,msg.document.file_id, msg.chat.id, msg.message_id)
    print(str(VT_states.check_ip_file))
    print(current_state)
    dir_name, table_name = {
        VT_states.check_ip_file: ('virustotal', Vt_ip),
        VT_states.check_ip_file_command: ('virustotal', Vt_ip),
        IPI_states.check_ip_file: ('ipinfo', Ipi_ip),
        IPI_states.check_ip_file_command: ('ipinfo', Ipi_ip),
        ADB_states.check_ip_file: ('abuseipdb', Abuseipdb),
        ADB_states.check_ip_file_command: ('abuseipdb', Abuseipdb),
        KSP_states.check_ip_file: ('kaspersky', Kaspersky),
        KSP_states.check_ip_file_command: ('kaspersky', Kaspersky),
        CIP_states.check_ip_file: ('criminalip', CriminalIP),
        CIP_states.check_ip_file_command: ('criminalip', CriminalIP),
        ALV_states.check_ip_file: ('alienvault', Alienvault),
        ALV_states.check_ip_file_command: ('alienvault', Alienvault),
    }[current_state]

    os.makedirs(f'data/{dir_name}', exist_ok=True)

    increment = 1
    while True:
        file_name = f'data/{dir_name}/ip{increment}.txt'
        if not os.path.exists(file_name):
            break
        increment += 1

    await bot.download_file(file.file_path, file_name)
    await orm_query.orm_queryorm_add_file_history(session, msg.message_id, file_name)

    with open(file_name, 'r', encoding='UTF-8') as file:
        text_file = file.read()

    ips, dnss = extract_and_validate(text_file)
    if not ips and not dnss:
        os.remove(file_name)
        return False, None

    db_ips, db_dnss = await process_db_ip(ips, dnss, session, table_name)

    result, reports = await info_function(ips, dnss)

    combined_reports  = db_ips + db_dnss + reports

    if not combined_reports : return False, None

    for report in reports:
        await db_function(session, report)

    if current_state == VT_states.check_ip_file or current_state == VT_states.check_ip_file_command:
        if len(combined_reports) > 1:
            answer = format.listdict_to_string_vt(combined_reports)
        else:
            format_dict = format.format_to_output_dict_vt(combined_reports[0])
            answer = format.dict_to_string(format_dict)
    format_dict_func = {
        IPI_states.check_ip_file: format.format_to_output_dict_ipi,
        IPI_states.check_ip_file_command: format.format_to_output_dict_ipi,
        ADB_states.check_ip_file: format.format_to_output_dict_adb,
        ADB_states.check_ip_file_command: format.format_to_output_dict_adb,
        KSP_states.check_ip_file: format.format_to_output_dict_ksp,
        KSP_states.check_ip_file_command: format.format_to_output_dict_ksp,
        CIP_states.check_ip_file: format.format_to_output_dict_cip,
        CIP_states.check_ip_file_command: format.format_to_output_dict_cip,
        ALV_states.check_ip_file: format.format_to_output_dict_alv,
        ALV_states.check_ip_file_command: format.format_to_output_dict_alv,
    }
    format_reports = [format_dict_func[current_state](report) for report in combined_reports]
    answer = format.listdict_to_string(format_reports)
    return True, answer
