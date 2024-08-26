from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from states import Gen
from middleware.virustotal import get_info_ip, get_ip_list_info
from middleware.ipinfo import get_info

import kb
import os
import text

router = Router()

# Обработчик вывода меню
@router.message(Command("start"))
async def start_handler(msg: Message, state: FSMContext):
    await state.set_state(Gen.start)
    await msg.answer(text.greetings.format(name=msg.from_user.full_name), reply_markup=kb.start_menu)

# Обработчик вывода освновного меню
@router.callback_query(F.data.in_({"start", "view_menu", "Меню", "Выйти в меню", "◀️ Выйти в меню"}))
async def menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.main_menu)
    await clbck.message.edit_text(text.menu, reply_markup=kb.start_menu)
    await clbck.answer('Меню')

# Обработчик вывода освновного меню
@router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
async def menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.help)
    await clbck.message.edit_text(text.help, reply_markup=kb.iexit_kb)
    await clbck.answer('Помощь')

@router.callback_query(F.data == "check_menu")
async def view_check_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_menu)
    await clbck.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
    await clbck.answer('Проверка IP')

@router.callback_query(F.data == "virustotal_menu")
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

@router.callback_query(F.data == "ipinfo_menu")
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)
