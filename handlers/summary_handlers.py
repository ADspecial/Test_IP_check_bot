from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode


from states import Base_states, Summary_states, VT_states, IPI_states, ADB_states, KSP_states, CIP_states, ALV_states, IPQS_states

from ipcheckers import alienvault, virustotal, abuseipdb, kaspersky, ipqualityscore, criminalip, ipinfo
from database.models import Ipinfo, Virustotal, Abuseipdb, Kaspersky, CriminalIP, Alienvault, Ipqualityscore
from ipcheckers import format
from ipcheckers.valid_ip import extract_and_validate

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import os
import database.orm_query as orm_query

sum_router = Router()

CHECKERS_MAP = {
    alienvault.get_alienvault_info: (ALV_states.check_ip, 'Alienvault', Alienvault, orm_query.orm_add_alienvault_data, format.format_to_output_dict_alv),
    virustotal.get_vt_info: (VT_states.check_ip, 'Virustotal', Virustotal, orm_query.orm_add_vt_ip, format.format_to_output_dict_vt),
    abuseipdb.get_abuseipdb_info: (ADB_states.check_ip, 'Abuseipdb', Abuseipdb, orm_query.orm_add_abuseipdb, format.format_to_output_dict_adb),
    kaspersky.get_kaspersky_info: (KSP_states.check_ip, 'Kaspersky', Kaspersky, orm_query.orm_add_kaspersky_data, format.format_to_output_dict_ksp),
    ipqualityscore.get_ipqs_info: (IPQS_states.check_ip, 'Ipqualityscore', Ipqualityscore, orm_query.orm_add_ipqs_data, format.format_to_output_dict_ipqs),
    #criminalip.get_criminalip_info: (CIP_states.check_ip,'Criminalip', CriminalIP,orm_query.orm_add_criminalip_data, format.format_to_output_dict_cip),
    ipinfo.get_ipi_info: (IPI_states.check_ip, 'Ipinfo', Ipinfo, orm_query.orm_add_ipi_ip, format.format_to_output_dict_ipi)
}

@sum_router.callback_query(F.data == "summary_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Summary_states.check_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_summary)

@sum_router.message(Summary_states.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id - 1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)

    mesg = await msg.answer(text.gen_wait)

    ip_list, dns_list = extract_and_validate(msg.text)

    if not ip_list and not dns_list:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
        return

    summary_report = {}

    for checker in CHECKERS_MAP:
        try:
            check_state, keyname, tablename, db_function, format_func = CHECKERS_MAP[checker]
            await state.set_state(check_state)

            # Обрабатываем IP и DNS из базы данных
            db_ips, db_dnss = await process.process_db_ip(ip_list.copy(), dns_list.copy(), session, tablename)

            # Выполняем проверку
            reports = []
            if ip_list or dns_list:
                result, reports = await checker(ip_list.copy(), dns_list.copy())  # Используем копии

            combined_reports = db_ips + db_dnss + reports

            if not combined_reports:
                await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
                return

            # Сохраняем отчеты в базу данных
            for report in reports:
                await db_function(session, report)

            # Форматируем отчеты
            format_reports = [format_func(report) for report in combined_reports]
            summary_report[keyname] = format_reports
        except Exception as e:
            print(f"Ошибка при обработке {checker}: {e}")
            await mesg.edit_text(text.err_processing.format(service=checker), reply_markup=kb.back_summary)
            return

    result = format.summary_format(summary_report)

    await mesg.edit_text(result, parse_mode=ParseMode.MARKDOWN)
    await mesg.answer(text.about_check_ip, reply_markup=kb.back_summary)

    await state.set_state(Summary_states.check_ip)

@sum_router.message(Command("sumcheck"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(Summary_states.check_ip)
    pattern = r'^/sumcheck\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        mesg = await msg.answer(text.gen_wait)

        ip_list, dns_list = extract_and_validate(msg.text)

        if not ip_list and not dns_list:
            await mesg.edit_text(text.err_ip)
            return

        summary_report = {}

        for checker in CHECKERS_MAP:
            try:
                check_state, keyname, tablename, db_function, format_func = CHECKERS_MAP[checker]
                await state.set_state(check_state)

                # Обрабатываем IP и DNS из базы данных
                db_ips, db_dnss = await process.process_db_ip(ip_list.copy(), dns_list.copy(), session, tablename)

                # Выполняем проверку
                reports = []
                if ip_list or dns_list:
                    result, reports = await checker(ip_list.copy(), dns_list.copy())  # Используем копии

                combined_reports = db_ips + db_dnss + reports

                if not combined_reports:
                    await mesg.edit_text(text.err_ip)
                    return

                # Сохраняем отчеты в базу данных
                for report in reports:
                    await db_function(session, report)

                # Форматируем отчеты
                format_reports = [format_func(report) for report in combined_reports]
                summary_report[keyname] = format_reports
            except Exception as e:
                print(f"Ошибка при обработке {checker}: {e}")
                await mesg.edit_text(text.err_processing.format(service=checker), reply_markup=kb.back_summary)
                return

        result = format.summary_format(summary_report)

        await mesg.edit_text(result, parse_mode=ParseMode.MARKDOWN)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Base_states.start)

@sum_router.callback_query(F.data == "summary_file")
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, kb.back_summary, Summary_states.check_ip_file, Summary_states.check_ip_file_command)

@sum_router.message(Command("sumfile"))
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, None, Summary_states.check_ip_file, Summary_states.check_ip_file_command)

@sum_router.message(Summary_states.check_ip_file)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.back_kaspersky)
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        current_state = await state.get_state()
        dir_name = 'summary'

        os.makedirs(f'data/{dir_name}', exist_ok=True)
        file_id = msg.document.file_id
        file = await bot.get_file(file_id)


        file_name = next(f'data/{dir_name}/ip{num}.txt' for num in range(1, 1000) if not os.path.exists(f'data/{dir_name}/ip{num}.txt'))

        await bot.download_file(file.file_path, file_name)
        await orm_query.orm_add_file_history(session, msg.message_id, file_name)

        with open(file_name, 'r', encoding='UTF-8') as file:
            text_file = file.read()
        ip_list, dns_list = extract_and_validate(text_file)

        if not ip_list and not dns_list:
            await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
            return

        summary_report = {}

        for checker in CHECKERS_MAP:
            try:
                check_state, keyname, tablename, db_function, format_func = CHECKERS_MAP[checker]
                await state.set_state(check_state)

                # Обрабатываем IP и DNS из базы данных
                db_ips, db_dnss = await process.process_db_ip(ip_list.copy(), dns_list.copy(), session, tablename)

                # Выполняем проверку
                reports = []
                if ip_list or dns_list:
                    result, reports = await checker(ip_list.copy(), dns_list.copy())  # Используем копии

                combined_reports = db_ips + db_dnss + reports

                if not combined_reports:
                    await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
                    return

                # Сохраняем отчеты в базу данных
                for report in reports:
                    await db_function(session, report)

                # Форматируем отчеты
                format_reports = [format_func(report) for report in combined_reports]
                summary_report[keyname] = format_reports
            except Exception as e:
                print(f"Ошибка при обработке {checker}: {e}")
                await mesg.edit_text(text.err_processing.format(service=checker), reply_markup=kb.back_summary)
                return

        result = format.summary_format(summary_report)

        await mesg.edit_text(result, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_summary)
    await state.set_state(Summary_states.check_ip_file)

@sum_router.message(Summary_states.check_ip_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        current_state = await state.get_state()
        dir_name = 'summary'

        os.makedirs(f'data/{dir_name}', exist_ok=True)
        file_id = msg.document.file_id
        file = await bot.get_file(file_id)


        file_name = next(f'data/{dir_name}/ip{num}.txt' for num in range(1, 1000) if not os.path.exists(f'data/{dir_name}/ip{num}.txt'))

        await bot.download_file(file.file_path, file_name)
        await orm_query.orm_add_file_history(session, msg.message_id, file_name)

        with open(file_name, 'r', encoding='UTF-8') as file:
            text_file = file.read()
        ip_list, dns_list = extract_and_validate(text_file)

        if not ip_list and not dns_list:
            await mesg.edit_text(text.err_ip)
            return

        summary_report = {}

        for checker in CHECKERS_MAP:
            try:
                check_state, keyname, tablename, db_function, format_func = CHECKERS_MAP[checker]
                await state.set_state(check_state)

                # Обрабатываем IP и DNS из базы данных
                db_ips, db_dnss = await process.process_db_ip(ip_list.copy(), dns_list.copy(), session, tablename)

                # Выполняем проверку
                reports = []
                if ip_list or dns_list:
                    result, reports = await checker(ip_list.copy(), dns_list.copy())  # Используем копии

                combined_reports = db_ips + db_dnss + reports

                if not combined_reports:
                    await mesg.edit_text(text.err_ip)
                    return

                # Сохраняем отчеты в базу данных
                for report in reports:
                    await db_function(session, report)

                # Форматируем отчеты
                format_reports = [format_func(report) for report in combined_reports]
                summary_report[keyname] = format_reports
            except Exception as e:
                print(f"Ошибка при обработке {checker}: {e}")
                await mesg.edit_text(text.err_processing.format(service=checker))
                return
        result = format.summary_format(summary_report)
        await mesg.edit_text(result, parse_mode=ParseMode.MARKDOWN)
    await state.set_state(Summary_states.check_ip_file)
