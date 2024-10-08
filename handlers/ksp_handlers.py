from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, KSP_states

from ipcheckers import kaspersky

from handlers import support

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query

ksp_router = Router()

@ksp_router.callback_query(F.data == "ksp_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(KSP_states.check_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_kaspersky)

@ksp_router.message(KSP_states.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    result, reports = await support.process_ip(msg, kaspersky.get_kaspersky_info, orm_query.orm_add_kaspersky_data, state, session)
    mesg = await msg.answer(text.gen_wait)
    if result:
        await mesg.edit_text(reports)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_kaspersky)
    else:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_kaspersky)

@ksp_router.message(Command("ksp_checkip"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(KSP_states.check_ip)
    pattern = r'^/ksp_checkip\s+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        result, report = await support.process_ip(msg, kaspersky.get_kaspersky_info, orm_query.orm_add_kaspersky_data, state, session)
        mesg = await msg.answer(text.gen_wait)
        if result:
            await mesg.edit_text(report)
        else:
            await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
            await mesg.edit_text(text.err_ip)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')

@ksp_router.callback_query(F.data == "ksp_file")
@ksp_router.message(Command("ksp_checkipfile"))
async def get_file(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await support.handle_file_request(msg_or_callback, state, text.send_text_file, kb.back_kaspersky,KSP_states.check_ip_file, KSP_states.check_ip_file_command)

@ksp_router.message(KSP_states.check_ip_file)
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
        result, report = await support.process_document(msg, bot,  kaspersky.get_kaspersky_info, orm_query.orm_add_kaspersky_data, state, session)
        if result:
            await mesg.edit_text(report)
            await msg.answer(text.send_text_file, reply_markup=kb.back_kaspersky)
    await state.set_state(KSP_states.check_ip_file)

@ksp_router.message(KSP_states.check_ip_file_command)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    if msg.document.mime_type != 'text/plain':
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).")
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        mesg = await msg.answer(text.gen_wait)
        result, report = await support.process_document(msg, bot,  kaspersky.get_kaspersky_info, orm_query.orm_add_kaspersky_data, state, session)
    if result:
        await mesg.edit_text(report)
    await state.set_state(Base_states.start)