from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, IPQS_states

from ipcheckers import ipqualityscore

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query

ipqs_router = Router()

@ipqs_router.callback_query(F.data == "ipqs_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(IPQS_states.check_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_ipqualityscore)

@ipqs_router.message(IPQS_states.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    result, reports = await process.process_ip(msg, ipqualityscore.get_ipqs_info, orm_query.orm_add_ipqs_data, state, session)
    mesg = await msg.answer(text.gen_wait)
    if result:
        await mesg.edit_text(reports)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_ipqualityscore)
    else:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_ipqualityscore)

@ipqs_router.message(Command("ipqscheck"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(IPQS_states.check_ip)
    pattern = r'^/ipqscheck\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        result, report = await process.process_ip(msg, ipqualityscore.get_ipqs_info, orm_query.orm_add_ipqs_data, state, session)
        mesg = await msg.answer(text.gen_wait)
        if result:
            await mesg.edit_text(report)
        else:
            await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
            await mesg.edit_text(text.err_ip)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')

@ipqs_router.callback_query(F.data == "ipqs_file")
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, kb.back_ipqualityscore,IPQS_states.check_ip_file, IPQS_states.check_ip_file_command)

@ipqs_router.message(Command("ipqsfile"))
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await process.handle_file_request(msg_or_callback, state, text.send_text_file, None, IPQS_states.check_ip_file, IPQS_states.check_ip_file_command)


@ipqs_router.message(IPQS_states.check_ip_file)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if not msg.document:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.back_ipqualityscore)
        return
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        result, report = await process.process_document(msg, bot, ipqualityscore.get_ipqs_info, orm_query.orm_add_ipqs_data, state, session)
        if result:
            await mesg.edit_text(report)
            await msg.answer(text.send_text_file, reply_markup=kb.back_ipqualityscore)
    await state.set_state(IPQS_states.check_ip_file)

@ipqs_router.message(IPQS_states.check_ip_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if not msg.document:
        await state.set_state(Base_states.start)
        await msg.answer("Вы не отправили файл")
        return
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        result, report = await process.process_document(msg, bot, ipqualityscore.get_ipqs_info, orm_query.orm_add_ipqs_data, state, session)
    if result:
        await mesg.edit_text(report)
    await state.set_state(Base_states.start)
