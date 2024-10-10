from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.exceptions import TelegramBadRequest

from filters.chat_type import ChatTypeFilter

from states import Base_states

import kb
import text


menu_router = Router()
message_ids_to_delete = []
last_user_message_id = {}

# Обработчик вывода меню
@menu_router.message(
    Command("start"),
    ChatTypeFilter(chat_type=["private"]))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Base_states.start)
    await msg.answer(text.greetings.format(name=msg.from_user.full_name), reply_markup=kb.start_menu)

@menu_router.message(
    Command("start"),
    ChatTypeFilter(chat_type=["group", "supergroup"]))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Base_states.start)
    await msg.answer(text.greetings_group.format(name=msg.from_user.full_name))

# Обработчик вывода освновного меню
@menu_router.message(Command("menu"))
@menu_router.callback_query(F.data.in_({"start", "view_menu", "Меню", "Выйти в меню", "◀️ Выйти в меню"}))
async def menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.main_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.menu, reply_markup=kb.start_menu)
        await msg_or_callback.answer('Меню')
    else:
        await msg_or_callback.answer(text.menu, reply_markup=kb.start_menu)

# Обработчик вывода помощи
@menu_router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
@menu_router.message(Command("help"))
async def help_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.help)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(help, reply_markup=kb.iexit_kb)
        await msg_or_callback.answer('Помощь')
    else:
        await msg_or_callback.answer(help)

# Обработчик вывода меню проверки IP
@menu_router.callback_query(F.data == "check_menu")
@menu_router.message(Command("check_menu"))
async def check_menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.check_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
        await msg_or_callback.answer('Проверка IP')
    else:
        await msg_or_callback.answer(text.check_menu, reply_markup=kb.check_menu)

# Обработчик вывода меню virustotal
@menu_router.callback_query(F.data == "virustotal_menu")
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

# Обработчик вывода меню ipinfo
@menu_router.callback_query(F.data == "ipinfo_menu")
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)

@menu_router.callback_query(F.data == "adbuseip_menu")
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.adbuseip_menu)
    await clbck.answer('AbuseIPDB menu')
    await clbck.message.edit_text(text.adbuseip_menu, reply_markup=kb.adbuseip_menu)

@menu_router.callback_query(F.data == "kaspersky_menu")
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.kaspersky_menu)
    await clbck.answer('Kaspersky menu')
    await clbck.message.edit_text(text.kaspersky_menu, reply_markup=kb.kaspersky_menu)

@menu_router.callback_query(F.data == "criminalip_menu")
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.criminalip_menu)
    await clbck.answer('CriminalIP menu')
    await clbck.message.edit_text(text.criminalip_menu, reply_markup=kb.criminalip_menu)

@menu_router.callback_query(F.data == "alienvault_menu")
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.alienvault_menu)
    await clbck.answer('AlienVault menu')
    await clbck.message.edit_text(text.alienvault_menu, reply_markup=kb.alienvault_menu)
