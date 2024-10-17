from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from itertools import zip_longest

from states import Base_states, Block_states

from ipcheckers.valid_ip import extract_and_validate, is_valid_ip

from handlers import format

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query

block_router = Router()

@block_router.callback_query(F.data == "create_blcoklist")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Block_states.blocklist_name)
    await clbck.message.edit_text("Введите имя блокировки:", reply_markup=kb.back_block)

@block_router.message(Block_states.blocklist_name)
async def process_name(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Block_states.blocklist_bid)
    await msg.answer("Введите номер заявки:")

@block_router.message(Block_states.blocklist_bid)
async def process_bid(msg: Message, state: FSMContext, bot:Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    try:
        bid = int(msg.text)
        await state.update_data(bid=bid)
        await state.set_state(Block_states.blocklist_description)
        await msg.answer("Введите описание:")
    except ValueError:
        await msg.answer("Пожалуйста, введите номер заявки (целое число):")

@block_router.message(Block_states.blocklist_description)
async def process_description(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(description=msg.text)
    await state.set_state(Block_states.blocklist_iplist)

    await msg.answer("Введите ip адреса блокировки:")

@block_router.message(Block_states.blocklist_iplist)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    data = await state.get_data()
    ips, dnss = extract_and_validate(msg.text)
    block_list = ips + dnss
    result = await orm_query.create_blocklist(session, block_list, data['name'], data['description'], msg.from_user.id, int(data['bid']))
    if result:
        output = await format.block_output(block_list)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer("Повторить добавление блолиста?", reply_markup=kb.repeat_add_blocklist)
    else:
        await mesg.edit_text("Ошибка создания блоклиста", reply_markup=kb.repeat_add_blocklist)


@block_router.message(Command("create_blocklist"))
async def create_blocklist_handler(msg: Message, state: FSMContext, session: AsyncSession):
    # Извлекаем текст после команды
    mesg = await msg.answer(text.gen_wait)
    args =msg.text.split()[1:]  # Получаем все аргументы после команды

    if len(args) < 4:
        await mesg.edit_text("Пожалуйста, укажите все параметры: name bid description ip_list")
        return

    name = args[0]  # Имя
    try:
        bid = int(args[1])  # Пробуем преобразовать в int
    except ValueError:
        await mesg.edit_text("Номер заявки должен быть целым числом.")
        return

    description = ''  # Описание

    # Остальные аргументы считаем IP-адресами
    ip_list = args[2:]  # Все последующие элементы будут IP-адресами

    # Проверка на корректность IP-адресов (можно добавить более сложную проверку)
    for ip in ip_list:
        if not is_valid_ip(ip):
            await mesg.edit_text(f"Некорректный IP-адрес: {ip}. Пожалуйста, проверьте ввод.")
            return

    result = await orm_query.create_blocklist(session, ip_list, name, description, msg.from_user.id, bid)
    if result:
        output = await format.block_output(ip_list)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка создания блоклиста")


@block_router.callback_query(F.data == "view_block")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Block_states.view)
    await clbck.message.edit_text(text.view_input, reply_markup=kb.view_input)


@block_router.message(Block_states.view)
@flags.chat_action("typing")
async def view_block(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    try:
        number = int(msg.text)
        output_list = await orm_query.get_blocked_ips(session, number)
        print(output_list)
        output = await format.block_view(output_list, number)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer(text.view_input, reply_markup=kb.view_input)
    except ValueError:
        await mesg.edit_text('Ошибка! Число не введено', reply_markup=kb.view_input)
