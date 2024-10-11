from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, ALV_states

from ipcheckers import alienvault

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

from filters.chat_type import ChatTypeFilter
from filters.admin_filter import AdminRightsFilter

import kb
import re
import text
import database.orm_query as orm_query

admin_router = Router()
admin_router.message.filter(ChatTypeFilter(chat_type=["private"]))
admin_router.message.filter(AdminRightsFilter(user_id=F.from_user.id))

@admin_router.message(Command("admin"))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Base_states.start)
    await msg.answer(text.admin_menu.format(name=msg.from_user.full_name, id=msg.from_user.id), reply_markup=kb.admin_menu)
