from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Sechost_states

from ipcheckers.valid_ip import extract_and_validate, is_valid_ip

from handlers import format

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import text
import database.orm_query as orm_query

sechost_router = Router()

@sechost_router.callback_query(F.data == "add_sechost")
async def start_process_create_bloсklist(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Sechost_states.add_name)
    await clbck.message.edit_text("Введите имя СЗИ:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_name)
async def process_name_bloсklist(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Sechost_states.add_description)
    await msg.answer("Введите описание:", reply_markup=kb.back_blocklist)
