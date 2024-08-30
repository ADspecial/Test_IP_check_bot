from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from states import Gen
from middleware.virustotal import get_info_ip, get_ip_list_info
from middleware.ipinfo import get_info
from middleware.format import dict_to_string, listdict_to_string

import kb
import re
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

# Обработчик вывода помощи
@router.callback_query(F.data.in_({"help", "помощь", "Помощь"}))
async def menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.help)
    await clbck.message.edit_text(text.help, reply_markup=kb.iexit_kb)
    await clbck.answer('Помощь')

# Обработчик вывода меню проверки IP
@router.callback_query(F.data == "check_menu")
async def view_check_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_menu)
    await clbck.message.edit_text(text.check_menu, reply_markup=kb.check_menu)
    await clbck.answer('Проверка IP')

# Обработчик вывода меню virustotal
@router.callback_query(F.data == "virustotal_menu")
async def view_virustotal_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.virustotal_menu)
    await clbck.answer('Проверка по virustotal')
    await clbck.message.edit_text(text.virustotal_menu, reply_markup=kb.virustotal_menu)

# Обработчик вывода меню ipinfo
@router.callback_query(F.data == "ipinfo_menu")
async def view_ipinfo_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.edit_text(text.ipinfo_menu, reply_markup=kb.ipinfo_menu)

@router.callback_query(F.data == "vt_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.vt_ip)
    await clbck.message.edit_text(text.about_check_ip,reply_markup=kb.back_vt)

@router.message(Gen.vt_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, state: FSMContext):
    await process_ip(msg, get_info_ip, text.err_ip, kb.back_vt)

@router.message(Command("vt_checkip"))
async def check_ip_command(msg: Message):
    match = re.match(r'^/vt_checkip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', msg.text)
    if match:
        await process_ip(msg, get_info_ip, text.err_ip, None)
    else:
        await msg.answer('Не введен ip адрес\n')

async def process_ip(msg: Message, info_function, error_text, back_kb):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = info_function(ip)
    if not res:
        return await mesg.edit_text(error_text, reply_markup=back_kb)
    if isinstance(res, list):
        await mesg.edit_text(listdict_to_string(res))
    else:
        await mesg.edit_text(dict_to_string(res))
    await mesg.answer(text.about_check_ip, reply_markup=back_kb)
