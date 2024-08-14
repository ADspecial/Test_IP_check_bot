# Bot handler functions

from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from includes.vt.checkip_vt import get_info_ip, get_ip_list_info
from states import Gen
from includes.IPinfo.ip_info import get_info

import kb
import os
import text

router = Router()

# Обработчик вывода меню
@router.message(Command("start"))
async def start_handler(msg: Message):
    await msg.answer(text.greet.format(name=msg.from_user.full_name), reply_markup=kb.start_menu)

# Обработчик вывода меню
@router.callback_query(F.data == "start")
@router.message(F.text == "Меню")
@router.message(F.text == "Выйти в меню")
@router.message(F.text == "◀️ Выйти в меню")
async def menu(msg: Message):
    await msg.answer(text.menu, reply_markup=kb.start_menu)

@router.callback_query(F.data == "check")
async def view_menu(clbck: CallbackQuery):
    await clbck.answer('Check IPs')
    await clbck.message.answer(text.check_menu, reply_markup=kb.check_ips)

@router.callback_query(F.data == "view_menu")
async def view_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.start)
    await clbck.answer('back to menu')
    await clbck.message.answer(text.menu, reply_markup=kb.start_menu)

@router.callback_query(F.data == "virustotal")
async def view_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.virustotal_menu)
    await clbck.answer('virustotal menu')
    await clbck.message.answer(text.virustotal_menu, reply_markup=kb.menu_check_vt)

@router.callback_query(F.data == "IPinfo")
async def view_menu(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipinfo_menu)
    await clbck.answer('IPinfo menu')
    await clbck.message.answer(text.ipinfo_menu, reply_markup=kb.menu_check_ipinfo)


@router.callback_query(F.data == "about_ip_ipinfo")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.about_ip_ipinfo)
    await clbck.message.edit_text(text.check_ips_list)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.back_ipinfo)

@router.message(Gen.about_ip_ipinfo)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, state: FSMContext):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = get_info(ip)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.back_ipinfo)
    await mesg.edit_text(res, reply_markup=kb.back_ipinfo)

@router.callback_query(F.data == "about_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.about_ip)
    await clbck.message.edit_text(text.about_check_ip)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.back_vt)

@router.message(Gen.about_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, state: FSMContext):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = get_info_ip(ip)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.back_vt)
    str1 = '\n'.join(res)
    await mesg.edit_text(str1, reply_markup=kb.back_vt)


@router.callback_query(F.data == "check_ip_list")
async def input_check_ips(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_ips)
    await clbck.message.edit_text(text.check_ips_list)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.back_vt)

@router.message(Gen.check_ips)
@flags.chat_action("typing")
async def check_ips(msg: Message, state: FSMContext):
    text_ips_and_dns = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = get_ip_list_info(text_ips_and_dns)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.back_vt)
    str1 = '\n'.join(res)
    await mesg.edit_text(str1,reply_markup=kb.back_vt)

@router.callback_query(F.data == "get_file")
async def get_file(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.get_doc)
    await clbck.message.edit_text(text.send_text_file)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.back_vt)

@router.message(Gen.get_doc)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    # Проверяем, что файл является текстовым
    if msg.document.mime_type == 'text/plain':
        file_id = msg.document.file_id
        file = await bot.get_file(file_id)

        await bot.download_file(file.file_path, \
                                   f'{msg.document.file_name}')
        with open(msg.document.file_name, 'r', encoding='UTF-8') as file:
            text_file = file.read()
        mesg = await msg.answer(text.gen_wait)
        res = get_ip_list_info(text_file)
        if not res:
            return await mesg.edit_text(text.err_ip, reply_markup=kb.back_vt)
        str1 = '\n'.join(res)
        # Отправляем содержимое файла пользователю
        await mesg.edit_text(str1,reply_markup=kb.back_vt)
        os.remove(f'{msg.document.file_name}')
    else:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
        os.remove(f'{msg.document.file_name}')

@router.callback_query(F.data == "get_file_ipinfo")
async def get_file(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.get_doc_ipinfo)
    await clbck.message.edit_text(text.send_text_file)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.back_ipinfo)

@router.message(Gen.get_doc_ipinfo)
@flags.chat_action("typing")
async def handle_document(msg: Message, bot: Bot, state: FSMContext):
    # Проверяем, что файл является текстовым
    if msg.document.mime_type == 'text/plain':
        file_id = msg.document.file_id
        file = await bot.get_file(file_id)

        await bot.download_file(file.file_path, \
                                   f'{msg.document.file_name}')
        with open(msg.document.file_name, 'r', encoding='UTF-8') as file:
            text_file = file.read()
        mesg = await msg.answer(text.gen_wait)
        res = get_info(text_file)
        if not res:
            return await mesg.edit_text(text.err_ip, reply_markup=kb.back_ipinfo)
        # Отправляем содержимое файла пользователю
        await mesg.edit_text(res,reply_markup=kb.back_ipinfo)
        os.remove(f'{msg.document.file_name}')
    else:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
        os.remove(f'{msg.document.file_name}')

@router.message(Command("help"))
async def cmd_help(msg: Message):
    await msg.answer("Вы нажали кнопку HELP)")
