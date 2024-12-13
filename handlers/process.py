from itertools import zip_longest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message, ReplyKeyboardMarkup

from database.models import Ipinfo, Virustotal, Abuseipdb, Kaspersky, CriminalIP, Alienvault, Ipqualityscore
from database import orm_query

from handlers import format
from ipcheckers.valid_ip import extract_and_validate
from ipcheckers import alienvault, virustotal, abuseipdb, kaspersky, ipqualityscore, criminalip, ipinfo

from states import VT_states, IPI_states, ADB_states, KSP_states, CIP_states, ALV_states, IPQS_states, Base_states

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

CHECKERS_MAP = {
    alienvault.get_alienvault_info: (ALV_states.check_ip, 'Alienvault', Alienvault, orm_query.orm_add_alienvault_data, format.format_to_output_dict_alv),
    virustotal.get_vt_info: (VT_states.check_ip, 'Virustotal', Virustotal, orm_query.orm_add_vt_ip, format.format_to_output_dict_vt),
    abuseipdb.get_abuseipdb_info: (ADB_states.check_ip, 'Abuseipdb', Abuseipdb, orm_query.orm_add_abuseipdb, format.format_to_output_dict_adb),
    kaspersky.get_kaspersky_info: (KSP_states.check_ip, 'Kaspersky', Kaspersky, orm_query.orm_add_kaspersky_data, format.format_to_output_dict_ksp),
    ipqualityscore.get_ipqs_info: (IPQS_states.check_ip, 'Ipqualityscore', Ipqualityscore, orm_query.orm_add_ipqs_data, format.format_to_output_dict_ipqs),
    #criminalip.get_criminalip_info: (CIP_states.check_ip,'Criminalip', CriminalIP,orm_query.orm_add_criminalip_data, format.format_to_output_dict_cip),
    ipinfo.get_ipi_info: (IPI_states.check_ip, 'Ipinfo', Ipinfo, orm_query.orm_add_ipi_ip, format.format_to_output_dict_ipi)
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

    ips, dnss =  await download_and_read_file(dir_name, msg, session, bot)

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

async def all_checkers(
    ip_list: List[str],
    dns_list: List[str],
    state: FSMContext,
    session: AsyncSession,
) -> Tuple[bool, str, List[str]]:
    """
    Запустить все доступные чекеры для заданных IP-адресов и DNS-имен.

    Аргументы:
        ip_list: Список IP-адресов для проверки.
        dns_list: Список DNS-имен для проверки.
        state: Текущее состояние пользователя.
        session: Асинхронная сессия базы данных.

    Возвращает:
        Кортеж, где первый элемент - булево значение, указывающее на успех,
        а второй элемент - строка, содержащая отчет.
    """
    summary_report: Dict[str, List[Dict[str, Union[str, int]]]] = {}
    error = []
    for checker in CHECKERS_MAP:
        ips = ip_list.copy()
        dns = dns_list.copy()
        try:
            check_state, keyname, tablename, db_function, format_func = CHECKERS_MAP[checker]
            await state.set_state(check_state)

            db_ips, db_dnss = await process_db_ip(ips, dns, session, tablename)

            reports: List[Dict[str, Union[str, int]]] = []
            if ips or dns:
                result, reports = await checker(ips, dns)

            combined_reports = db_ips + db_dnss + reports

            if not combined_reports:
                error.append(keyname)
                continue

            for report in reports:
                await db_function(session, report)

            format_reports = [format_func(report) for report in combined_reports]
            summary_report[keyname] = format_reports
            await state.set_state(Base_states.start)
        except Exception as e:
            print(f"Ошибка при обработке {checker}: {e}")
            error.append(keyname)
            continue
    if not summary_report:
        return False, None, error
    else:
        return True, format.summary_format(summary_report), error

from typing import List, Tuple

async def download_and_read_file(
    dir_name: str, msg: Message, session: AsyncSession, bot: Bot
) -> Tuple[List[str], List[str]]:
    """
    Download and read a file from Telegram.

    Args:
        dir_name (str): The directory to store the file in.
        msg (Message): The message containing the file.
        session (AsyncSession): The async session to use for the database.
        bot (Bot): The bot to use for the Telegram API.

    Returns:
        Tuple[List[str], List[str]]: A tuple containing lists of IPs and DNS names extracted from the file.
    """
    dir_path = os.path.join("data", dir_name)
    os.makedirs(dir_path, exist_ok=True)

    file_id = msg.document.file_id
    file = await bot.get_file(file_id)

    file_name = os.path.join(dir_path, f"{file_id}.txt")

    await bot.download_file(file.file_path, file_name)

    await orm_query.orm_add_file_history(session, msg.message_id, file_name)

    with open(file_name, "r", encoding="UTF-8") as file:
        text_file = file.read()

    ips, dnss = extract_and_validate(text_file)
    if not ips and not dnss:
        os.remove(file_name)
        return [], []

    return ips, dnss
