# Функции-обработчики бота

from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from includes.single_ip import ip_info
from includes.ip_list import check_ip_list
from states import Gen

import kb
import os
import text

router = Router()

# Обработчик вывода меню
@router.message(Command("start"))
async def start_handler(msg: Message):
    await msg.answer(text.greet.format(name=msg.from_user.full_name), reply_markup=kb.menu)

# Обработчик вывода меню
@router.callback_query(F.data == "start")
@router.message(F.text == "Меню")
@router.message(F.text == "Выйти в меню")
@router.message(F.text == "◀️ Выйти в меню")
async def menu(msg: Message):
    await msg.answer(text.menu, reply_markup=kb.menu)

@router.callback_query(F.data == "view_menu")
async def view_menu(clbck: CallbackQuery):
    await clbck.answer('back to menu')
    await clbck.message.answer(text.menu, reply_markup=kb.menu)

@router.callback_query(F.data == "about_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.about_ip)
    await clbck.message.edit_text(text.about_check_ip)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.iexit_kb)

@router.message(Gen.about_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, state: FSMContext):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = ip_info(ip)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.iexit_kb)
    str1 = '\n'.join(res)
    await mesg.edit_text(str1, reply_markup=kb.iexit_kb)


@router.callback_query(F.data == "check_ip_list")
async def input_check_ips(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_ips)
    await clbck.message.edit_text(text.check_ips_list)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.iexit_kb)

@router.message(Gen.check_ips)
@flags.chat_action("typing")
async def check_ips(msg: Message, state: FSMContext):
    text_ips_and_dns = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = check_ip_list(text_ips_and_dns)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.iexit_kb)
    str1 = '\n'.join(res)
    await mesg.edit_text(str1,reply_markup=kb.iexit_kb)

@router.callback_query(F.data == "get_file")
async def get_file(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.get_doc)
    await clbck.message.edit_text(text.send_text_file)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.iexit_kb)

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
        res = check_ip_list(text_file)
        if not res:
            return await mesg.edit_text(text.err_ip, reply_markup=kb.iexit_kb)
        str1 = '\n'.join(res)
        # Отправляем содержимое файла пользователю
        await mesg.edit_text(str1,reply_markup=kb.iexit_kb)
        os.remove(f'{msg.document.file_name}')
        await state.set_state(Gen.start)
    else:
        await msg.answer("Пожалуйста, отправьте текстовый файл (.txt).", reply_markup=kb.iexit_kb)
        os.remove(f'{msg.document.file_name}')
        await state.set_state(Gen.start)

@router.message(Command("help"))
async def cmd_help(msg: Message):
    await msg.answer("Вы нажали кнопку HELP)")
