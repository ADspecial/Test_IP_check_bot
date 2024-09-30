from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Gen

from ipcheckers import ipinfo

from handlers import support

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query


ipi_router = Router()

# Обработчик для вывода инфы об ip по ipinfo
@ipi_router.callback_query(F.data == "ipi_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipi_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_vt)

@ipi_router.message(Gen.ipi_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    result, reports = await support.process_ip(msg, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, 'ipi', session)
    mesg = await msg.answer(text.gen_wait)
    if result:
        await mesg.edit_text(reports)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_ipinfo)
    else:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_ipinfo)

@ipi_router.message(Command("ipi_checkip"))
async def check_ip_command(msg: Message, state: FSMContext, bot: Bot, session: AsyncSession):
    await state.set_state(Gen.ipi_ip)
    pattern = r'^/ipi_checkip (?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\s+|$))+$'
    match = re.match(pattern, msg.text)
    if match:
        result, report = await support.process_ip(msg, ipinfo.get_ipi_info, orm_query.orm_add_ipi_ip, 'ipi', session)
        mesg = await msg.answer(text.gen_wait)
        if result:
            await mesg.edit_text(report)
        else:
            await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
            await mesg.edit_text(text.err_ip)
    else:
        await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
        await msg.answer('Не введен ip адрес\n')
    await state.set_state(Gen.start)
