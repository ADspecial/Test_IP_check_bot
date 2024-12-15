from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Summary_states, VT_states, IPI_states, ADB_states, KSP_states, CIP_states, ALV_states, IPQS_states
from ipcheckers import alienvault, virustotal, abuseipdb, kaspersky, ipqualityscore, criminalip, ipinfo
from database.models import Ipinfo, Virustotal, Abuseipdb, Kaspersky, CriminalIP, Alienvault, Ipqualityscore
from handlers import format
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
async def check_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id - 1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)

    mesg = await msg.answer(text.gen_wait)

    ip_list, dns_list = extract_and_validate(msg.text)

    if not ip_list and not dns_list:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
        return

    result, summary_report, error =  await process.all_checkers(ip_list, dns_list, state, session)

    if not result:  # Error message returned
        await mesg.edit_text(text.err_processing.format(service=error[-1]), reply_markup=kb.back_summary)
        return

    await mesg.edit_text(summary_report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    await mesg.answer(text.about_check_ip, reply_markup=kb.back_summary)
    await state.set_state(Summary_states.check_ip)

@sum_router.message(Command("check"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(Summary_states.check_ip)
    pattern = r'^/check\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+|$))+$'

    if re.match(pattern,msg.text):
        mesg = await msg.answer(text.gen_wait)
        ip_list,dns_list = extract_and_validate(msg.text)

        if not ip_list and not dns_list:
            await mesg.edit_text(text.err_ip)
            return

        result, summary_report, error = await process.all_checkers(ip_list, dns_list, state, session)

        if not result:  # Error message returned
            await mesg.edit_text(text.err_processing.format(service=error[-1]))
            return

        await mesg.edit_text(summary_report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Base_states.start)

@sum_router.callback_query(F.data == "summary_file")
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, kb.back_summary, Summary_states.check_ip_file, Summary_states.check_ip_file_command)

@sum_router.message(Command("checkfile"))
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, None, Summary_states.check_ip_file, Summary_states.check_ip_file_command)

@sum_router.message(Summary_states.check_ip_file)
@flags.chat_action("typing")
async def check_ip_file(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document and msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.back_summary)
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)

    mesg = await msg.answer(text.gen_wait)
    ip_list, dns_list = await process.download_and_read_file('summary', msg, session, bot)

    if not ip_list and not dns_list:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_summary)
        return

    result, summary_report, error = await process.all_checkers(ip_list, [], state, session)

    if not result:  # Error message returned
        await mesg.edit_text(text.err_processing.format(service=error[-1]), reply_markup=kb.back_summary)
        return

    await mesg.edit_text(summary_report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    await mesg.answer(text.send_text_file, reply_markup=kb.back_summary)
    await state.set_state(Summary_states.check_ip_file)

@sum_router.message(Summary_states.check_ip_file_command)
@flags.chat_action("typing")
async def check_ip_file_command(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document and msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)

    mesg = await msg.answer(text.gen_wait)
    ip_list, dns_list = await process.download_and_read_file('summary', msg, session, bot)

    if not ip_list and not dns_list:
        await mesg.edit_text(text.err_ip)
        return

    result, summary_report, error = await process.all_checkers(ip_list, [], state, session)

    if not result:  # Error message returned
        await mesg.edit_text(text.err_processing.format(service=error[-1]))
        return

    await mesg.edit_text(summary_report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    await state.set_state(Base_states.start)
