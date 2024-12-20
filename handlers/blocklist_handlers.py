from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Blocklist_states

from ipcheckers.valid_ip import extract_and_validate, is_valid_ip

from handlers import format

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import text
import database.orm_query as orm_query

blocklist_router = Router()

@blocklist_router.callback_query(F.data == "add_bloсklist")
async def start_process_create_bloсklist(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Blocklist_states.add_name)
    await clbck.message.edit_text("Введите имя блокировки:", reply_markup=kb.back_blocklist)

@blocklist_router.message(Blocklist_states.add_name)
async def process_name_bloсklist(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Blocklist_states.add_description)
    await msg.answer("Введите описание:", reply_markup=kb.back_blocklist)

@blocklist_router.message(Blocklist_states.add_description)
async def process_description_bloсklist(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(description=msg.text)
    await state.set_state(Blocklist_states.add)
    await msg.answer("Введите адреса для блокировки:", reply_markup=kb.back_blocklist)

@blocklist_router.message(Blocklist_states.add)
@flags.chat_action("typing")
async def process_create_blocklist(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    data = await state.get_data()
    ips, dnss = extract_and_validate(msg.text)
    block_list = ips + dnss
    result = await orm_query.create_or_update_blocklist(session, block_list, data['name'], data['description'], msg.from_user.id)
    if result == 1:
        output = await format.block_output(block_list)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer("Выберете действие:", reply_markup=kb.repeat_add_blocklist)
    else:
        await mesg.edit_text("Ошибка создания/обновления ЧС", reply_markup=kb.repeat_add_blocklist)

@blocklist_router.message(Command("add_blocklist"))
async def add_blocklist_command(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return
    mesg = await msg.answer(text.gen_wait)
    await state.set_state(Blocklist_states.add_command)
    args =msg.text.split()[1:]
    if len(args) < 1:
        await mesg.edit_text("Пожалуйста, укажите все параметры: name ip_list")
        return
    name = args[0]
    ip_list = args[1:]

    for ip in ip_list:
        if not is_valid_ip(ip):
            await mesg.edit_text(f"Некорректный IP-адрес: {ip}. Пожалуйста, проверьте ввод.")
            await state.set_state(Base_states.start)
            return
    result = await orm_query.create_or_update_blocklist(session, ip_list, name, '', msg.from_user.id)
    if result == 1:
        output = await format.block_output(ip_list)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка создания/обновления ЧС")
    await state.set_state(Base_states.start)


@blocklist_router.callback_query(F.data == "view_bloсklist")
async def start_process_view_blocklist(clbck: CallbackQuery, state: FSMContext):
    await clbck.message.edit_text("Введите количество дней за которое необходимо просмотреть ЧС:",reply_markup=kb.back_blocklist)
    await state.set_state(Blocklist_states.view)

@blocklist_router.message(Blocklist_states.view)
@flags.chat_action("typing")
async def view_blocklist(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    try:
        day = int(msg.text)
    except ValueError:
        await msg.edit_text("Количество дней должно быть числом", reply_markup=kb.repeat_view_blocklist)
        await state.set_state(Blocklist_states.menu)
        return
    await bot.delete_message(msg.chat.id, msg.message_id-2,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    end_time = date_time.now()
    start_time = end_time - datetime.timedelta(days=day)
    blocklists = await orm_query.get_blocklists_within_timeframe(session, start_time, end_time)
    if blocklists:
        output = await format.blocklist_info(blocklists, day, 'day')
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer("Выберете действие:", reply_markup=kb.repeat_view_blocklist)
    else:
        await mesg.edit_text("ЧС не найдены", reply_markup=kb.repeat_view_blocklist)
    await state.set_state(Blocklist_states.menu)

@blocklist_router.message(Command("view_blocklist"))
async def view_blocklist_command(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    mesg = await msg.answer(text.gen_wait)
    await state.set_state(Blocklist_states.view_command)
    args = msg.text.split()[1:]

    if len(args) < 1:
        await mesg.edit_text("Пожалуйста, укажите аргумент: 'all' для всех записей или int: time {sec, min, hour, day}")
        await state.set_state(Base_states.start)
        return

    if args[0].lower() == "all":
        blocklists = await orm_query.get_blocklists_within_timeframe(session)
        if blocklists:
            output = await format.blocklist_info(blocklists, None, None)
            await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        else:
            await mesg.edit_text("ЧС не найдены")
        await state.set_state(Base_states.start)
        return

    try:
        time = int(args[0])
    except ValueError:
        await mesg.edit_text("Первый параметр должен быть числом или 'all'")
        await state.set_state(Base_states.start)
        return

    if len(args) < 2:
        await mesg.edit_text("Пожалуйста, укажите единицу времени: sec, min, hour, day")
        await state.set_state(Base_states.start)
        return

    if args[1] == "sec":
        param = 'seconds'
    elif args[1] == "min":
        param = 'minutes'
    elif args[1] == "hour":
        param = 'hours'
    elif args[1] == "day":
        param = 'days'
    else:
        await mesg.edit_text("Второй параметр должен быть sec, min, hour, day")
        await state.set_state(Base_states.start)
        return

    end_time = date_time.now()
    start_time = end_time - datetime.timedelta(**{param: time})
    blocklists = await orm_query.get_blocklists_within_timeframe(session, start_time, end_time)

    if blocklists:
        output = await format.blocklist_info(blocklists, time, param)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("ЧС не найдены")

    await state.set_state(Base_states.start)

@blocklist_router.callback_query(F.data == "delete_bloсklist")
async def start_process_delete_bloсklist(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Blocklist_states.delete)
    await clbck.message.edit_text("Введите имена ЧС через пробел:", reply_markup=kb.back_blocklist)

@blocklist_router.message(Blocklist_states.delete)
@flags.chat_action("typing")
async def process_create_blocklist(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    names = msg.text.strip().split()
    mesg = await msg.answer(text.gen_wait)
    error_names = []
    success_names = []
    for name in names:
        result = await orm_query.delete_blocklist_by_name(session, str(name))
        if result:
            success_names.append(name)
        else:
            error_names.append(name)

    output = await format.delete_blocklist_info(success_names, error_names)
    # Отправляем ответ
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await mesg.answer("Выберете действие:", reply_markup=kb.repeat_delete_blocklist)

@blocklist_router.message(Command("delete_blocklist"))
@flags.chat_action("typing")
async def process_create_blocklist(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return
    mesg = await msg.answer(text.gen_wait)
    await state.set_state(Blocklist_states.delete_command)
    args = msg.text.split()[1:]
    if not args:
        await mesg.edit_text("Пожалуйста, введите имена ЧС через пробел: str: names")
        await state.set_state(Base_states.main_menu )
        return
    error_names = []
    success_names = []
    for name in args:
        result = await orm_query.delete_blocklist_by_name(session, str(name))
        if result:
            success_names.append(name)
        else:
            error_names.append(name)
    output = await format.delete_blocklist_info(success_names, error_names)
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await state.set_state(Base_states.main_menu )
