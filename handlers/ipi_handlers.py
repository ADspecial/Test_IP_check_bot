from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import IPI_states, Base_states

from ipcheckers import ipinfo

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query


ipi_router = Router()

# Обработчик для вывода инфы об ip по ipinfo
@ipi_router.callback_query(F.data == "ipi_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(IPI_states.check_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_ipinfo)

@ipi_router.message(IPI_states.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    result, reports = await process.process_ip(msg, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, state, session)
    mesg = await msg.answer(text.gen_wait)
    if result:
        await mesg.edit_text(reports)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_ipinfo)
    else:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_ipinfo)

@ipi_router.message(Command("ipicheck"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(IPI_states.check_ip)
    pattern = r'^/ipicheck (?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        result, report = await process.process_ip(msg, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, state, session)
        mesg = await msg.answer(text.gen_wait)
        if result:
            await mesg.edit_text(report)
        else:
            await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
            await mesg.edit_text(text.err_ip)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Base_states.start)

@ipi_router.callback_query(F.data == "ipi_file")
@ipi_router.message(Command("ipifile"))
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, kb.back_ipinfo,IPI_states.check_ip_file, IPI_states.check_ip_file_command)

@ipi_router.message(IPI_states.check_ip_file)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.back_ipinfo)
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        result, report = await process.process_document(msg, bot, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, state, session)
        if result:
            await mesg.edit_text(report)
            await msg.answer(text.send_text_file, reply_markup=kb.back_ipinfo)
    await state.set_state(IPI_states.check_ip_file)

@ipi_router.message(IPI_states.check_ip_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        result, report = await process.process_document(msg, bot, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, state, session)
    if result:
        await mesg.edit_text(report)
    await state.set_state(Base_states.start)
