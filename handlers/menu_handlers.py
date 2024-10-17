from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.exceptions import TelegramBadRequest
from aiogram.enums import ParseMode
from aiogram.utils.deep_linking import create_start_link


from filters.chat_type import ChatTypeFilter

from states import Base_states

import kb
import text


menu_router = Router()
message_ids_to_delete = []
last_user_message_id = {}

# Обработчик команды старт для личного чата
@menu_router.message(
    Command("start"),
    ChatTypeFilter(chat_type=["private"]))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Base_states.start)
    await msg.answer(text.greetings.format(name=msg.from_user.full_name, id=msg.from_user.id), reply_markup=kb.start_menu, parse_mode=ParseMode.MARKDOWN)

# Обработчик команды старт для группового чата
@menu_router.message(
    Command("start"),
    ChatTypeFilter(chat_type=["group", "supergroup"]))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Base_states.start)
    await msg.answer(text.greetings_group.format(name=msg.from_user.full_name))

# Обработчик вывода освновного меню
@menu_router.message(
    Command("menu"),
    ChatTypeFilter(chat_type=["private"])
)
@menu_router.callback_query(F.data.in_({"start", "view_menu", "Меню", "Выйти в меню", "◀️ Выйти в меню"}))
async def menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.main_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.menu, reply_markup=kb.start_menu)
        await msg_or_callback.answer('Меню')
    else:
        await msg_or_callback.answer(text.menu, reply_markup=kb.start_menu)

# Обработчик вывода помощи для личного чата
@menu_router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
@menu_router.message(
    Command("help"),
    ChatTypeFilter(chat_type=["private"])
)
async def help_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.help)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.help_private,parse_mode=ParseMode.MARKDOWN, reply_markup=kb.iexit_kb)
        await msg_or_callback.answer('Помощь')
    else:
        await msg_or_callback.answer(text.help_private, parse_mode=ParseMode.MARKDOWN)

# Обработчик вывода помощи для группового чата
@menu_router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
@menu_router.message(
    Command("help"),
    ChatTypeFilter(chat_type=["group", "supergroup"])
)
async def help_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.help)
    await msg_or_callback.answer(text.help_group, parse_mode=ParseMode.MARKDOWN)

@menu_router.callback_query(F.data == "block_menu")
@menu_router.message(
    Command("blockmenu"),
    ChatTypeFilter(chat_type=["private"])
)
async def check_menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.block_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.block_menu, reply_markup=kb.block_menu)
        await msg_or_callback.answer('Блокировка IP')
    else:
        await msg_or_callback.answer(text.block_menu, reply_markup=kb.block_menu)



# Обработчик вывода меню проверки IP
@menu_router.callback_query(F.data == "check_menu")
@menu_router.message(
    Command("check_menu"),
    ChatTypeFilter(chat_type=["private"])
)
async def check_menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext, bot: Bot):
    await state.set_state(Base_states.check_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
        await msg_or_callback.answer('Проверка IP')
    else:
        await msg_or_callback.answer(text.check_menu, reply_markup=kb.check_menu)

# Обработчик вывода меню virustotal
@menu_router.callback_query(
    F.data == "virustotal_menu"
)
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

# Обработчик вывода меню ipinfo
@menu_router.callback_query(
    F.data == "ipinfo_menu"
)
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)

# Обработчик вывода меню abuseipdb
@menu_router.callback_query(
    F.data == "adbuseip_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.adbuseip_menu)
    await clbck.answer('AbuseIPDB menu')
    await clbck.message.edit_text(text.adbuseip_menu, reply_markup=kb.adbuseip_menu)

# Обработчик вывода меню kaspersky
@menu_router.callback_query(
    F.data == "kaspersky_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.kaspersky_menu)
    await clbck.answer('Kaspersky menu')
    await clbck.message.edit_text(text.kaspersky_menu, reply_markup=kb.kaspersky_menu)

# Обработчик вывода меню criminalip
@menu_router.callback_query(
    F.data == "criminalip_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.criminalip_menu)
    await clbck.answer('CriminalIP menu')
    await clbck.message.edit_text(text.criminalip_menu, reply_markup=kb.criminalip_menu)

# Обработчик вывода меню alienvault
@menu_router.callback_query(
    F.data == "alienvault_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.alienvault_menu)
    await clbck.answer('AlienVault menu')
    await clbck.message.edit_text(text.alienvault_menu, reply_markup=kb.alienvault_menu)

@menu_router.callback_query(
    F.data == "ipqualityscore_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.ipqualityscore_menu)
    await clbck.answer('IPQS menu')
    await clbck.message.edit_text(text.ipqualityscore_menu, reply_markup=kb.ipqualityscore_menu)

@menu_router.callback_query(
    F.data == "summary_menu"
)
async def view_adbuseip_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.summary_menu)
    await clbck.answer('Summary menu')
    await clbck.message.edit_text(text.summary_menu, reply_markup=kb.summary_menu)
