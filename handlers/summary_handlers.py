from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, Summary_states

from ipcheckers import alienvault, virustotal, abuseipdb, kaspersky, ipqualityscore, criminalip, ipinfo

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query

sum_router = Router()

@sum_router.callback_query(F.data == "summary_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Summary_states.check_ip)
    await clbck.message.edit_text(text.about_check_ip, reply_markup=kb.back_summary)

@sum_router.message(Summary_states.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    result, reports = await process.process_ip(msg, alienvault.get_alienvault_info, orm_query.orm_add_alienvault_data, state, session)
    mesg = await msg.answer(text.gen_wait)
    if result:
        await mesg.edit_text(reports)
        await mesg.answer(text.about_check_ip, reply_markup=kb.back_alienvault)
    else:
        await mesg.edit_text(text.err_ip, reply_markup=kb.back_alienvault)
