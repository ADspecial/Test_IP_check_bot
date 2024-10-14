from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, Admin_states

from ipcheckers import alienvault

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

from filters.chat_type import ChatTypeFilter

import kb
import re
import text
import database.orm_query as orm_query

admin_router = Router()
admin_router.message.filter(ChatTypeFilter(chat_type=["private"]))

@admin_router.message(Command("admin"))
async def start_admin_menu_handler(msg: Message, state: FSMContext, is_admin: bool):
    if is_admin:
        await state.set_state(Base_states.admin_menu)
        await msg.answer(text.start_admin_menu.format(name=msg.from_user.full_name), reply_markup=kb.admin_menu)
    else:
        await msg.answer(text.false_admin_menu.format(name=msg.from_user.full_name))

@admin_router.callback_query(F.data == "admin_menu")
async def admin_menu_handler(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.admin_menu)
    await clbck.message.edit_text(text.admin_menu, reply_markup=kb.admin_menu)

@admin_router.callback_query(F.data == "users_menu")
async def users_menu(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Admin_states.users_menu)
    await msg_or_callback.message.edit_text(text.users_menu, reply_markup=kb.users_menu)

@admin_router.callback_query(F.data == "add_admin")
async def add_admin_handler(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Admin_states.add_admin)
    await clbck.message.edit_text(text.about_add_admin, reply_markup=kb.back_users)

@admin_router.message(Admin_states.add_admin)
@flags.chat_action("typing")
async def add_admin(msg: Message, is_admin: bool, session: AsyncSession):
    if is_admin:
        username = msg.text.strip()
        try:
            result = await orm_query.grant_admin_rights(session, username)
            if result:
                await msg.answer(text.success_add_admin.format(username=username), reply_markup=kb.back_users)
            else:
                await msg.answer(text.err_add_admin.format(username=username), reply_markup=kb.back_users)
        except Exception as e:
            print(f"Ошибка при добавлении прав администратора: {e}")
            await msg.answer("Произошла ошибка при обработке запроса.", reply_markup=kb.back_users)
