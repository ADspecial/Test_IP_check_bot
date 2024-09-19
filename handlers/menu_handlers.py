from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.exceptions import TelegramBadRequest

from states import Gen

import kb
import text


menu_router = Router()
message_ids_to_delete = []

# Обработчик вывода меню
@menu_router.message(Command("start"))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Gen.start)
    await msg.answer(text.greetings.format(name=msg.from_user.full_name), reply_markup=kb.start_menu, parse_mode=None)

# Обработчик вывода освновного меню
@menu_router.message(Command("menu"))
@menu_router.callback_query(F.data.in_({"start", "view_menu", "Меню", "Выйти в меню", "◀️ Выйти в меню"}))
async def menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.main_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.menu, reply_markup=kb.start_menu)
        await msg_or_callback.answer('Меню')
    else:
        await msg_or_callback.answer(text.menu, reply_markup=kb.start_menu)

# Обработчик вывода помощи
@menu_router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
@menu_router.message(Command("help"))
async def help_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.help)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.help, reply_markup=kb.iexit_kb)
        await msg_or_callback.answer('Помощь')
    else:
        await msg_or_callback.answer(text.help)

# Обработчик вывода меню проверки IP
@menu_router.callback_query(F.data == "check_menu")
@menu_router.message(Command("check_menu"))
async def check_menu_handler(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_menu)
    if isinstance(msg_or_callback, CallbackQuery):
        await msg_or_callback.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
        await msg_or_callback.answer('Проверка IP')
    else:
        await msg_or_callback.answer(text.check_menu, reply_markup=kb.check_menu)

@menu_router.message(Command("clear"))
async def cmd_clear(message: Message, bot: Bot) -> None:
    try:
        for i in range(message.message_id, 0, -1):
            await bot.delete_message(message.from_user.id, i)
    except TelegramBadRequest as ex:
        if ex.message == "Bad Request: message to delete not found":
            print("Все сообщения удалены")

# Обработчик вывода меню virustotal
@menu_router.callback_query(F.data == "virustotal_menu")
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

# Обработчик вывода меню ipinfo
@menu_router.callback_query(F.data == "ipinfo_menu")
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)
