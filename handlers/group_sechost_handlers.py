from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, GroupSechost_states

from ipcheckers.valid_ip import is_valid_ip

from handlers import format

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import text
import database.orm_query as orm_query

group_sechost_router = Router()

@group_sechost_router.callback_query(F.data == "add_group_sechost")
async def start_process_create_group_sechost(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(GroupSechost_states.add_name)
    await clbck.message.edit_text("Введите имя группы СЗИ:", reply_markup=kb.back_group_sechost)

@group_sechost_router.message(GroupSechost_states.add_name)
async def process_name_group_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(GroupSechost_states.add_description)
    await msg.answer("Введите описание группы СЗИ:", reply_markup=kb.back_group_sechost)

@group_sechost_router.message(GroupSechost_states.add_description)
async def process_description_group_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    await state.update_data(description=msg.text)
    await state.set_state(GroupSechost_states.add)
    await msg.answer("Введите адреса или имена СЗИ через пробел:", reply_markup=kb.back_group_sechost)

@group_sechost_router.message(GroupSechost_states.add)
@flags.chat_action("typing")
async def process_create_group_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    security_hosts = [host.strip() for host in msg.text.split()]
    await state.update_data(security_hosts=security_hosts)
    mesg = await msg.answer(text.gen_wait)
    data = await state.get_data()
    result = await orm_query.create_or_update_group_security_host(session, data['name'], data['description'], data['security_hosts'])
    if result:
        output = f"Группа СЗИ '{data['name']}' успешно добавлена или обновлена."
        await mesg.edit_text(output)
        await mesg.answer("Выберите действие:", reply_markup=kb.repeat_add_group_sechost)
    else:
        await mesg.edit_text("Ошибка создания/обновления группы СЗИ", reply_markup=kb.repeat_add_group_sechost)

@group_sechost_router.callback_query(F.data == "delete_group_sechost")
async def start_process_delete_group_sechost(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(GroupSechost_states.delete)
    await clbck.message.edit_text("Введите имена групп СЗИ через пробел для удаления:", reply_markup=kb.back_sechost)

@group_sechost_router.message(GroupSechost_states.delete)
@flags.chat_action("typing")
async def process_delete_group_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    group_names = msg.text.strip().split()
    mesg = await msg.answer(text.gen_wait)
    error = []
    success = []
    for group_name in group_names:
        result = await orm_query.delete_group_security_host(session, group_name)
        if result:
            success.append(group_name)
        else:
            error.append(group_name)

    output = await format.delete_group_sechost_info(success, error)
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await mesg.answer("Выберите действие:", reply_markup=kb.repeat_delete_group_sechost)

@group_sechost_router.callback_query(F.data == "view_group_sechost")
async def start_process_view_group_sechost(clbck: CallbackQuery, state: FSMContext):
    await clbck.message.edit_text("Введите 'all' или количество дней, за которое необходимо просмотреть группы СЗИ:", reply_markup=kb.back_sechost)
    await state.set_state(GroupSechost_states.view)

@group_sechost_router.message(GroupSechost_states.view)
@flags.chat_action("typing")
async def view_group_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    if msg.text.lower() == "all":
        start_time = None
        end_time = None
    else:
        try:
            day = int(msg.text)
            end_time = date_time.now()
            start_time = end_time - datetime.timedelta(days=day)
        except ValueError:
            await msg.answer("Количество дней должно быть числом или 'all' для полного периода", reply_markup=kb.repeat_view_group_sechost)
            await state.set_state(GroupSechost_states.menu)
            return

    await bot.delete_message(msg.chat.id, msg.message_id-2, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)

    mesg = await msg.answer(text.gen_wait)

    group_sechosts = await orm_query.get_group_security_hosts_within_timeframe(session, start_time, end_time)

    if group_sechosts:
        output = await format.group_sechost_info(group_sechosts, day if start_time else "все", "дней" if start_time else "время")
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await msg.answer("Выберите действие:", reply_markup=kb.repeat_view_group_sechost)
    else:
        await mesg.edit_text("Группы СЗИ не найдены", reply_markup=kb.repeat_view_group_sechost)

    await state.set_state(GroupSechost_states.menu)



@group_sechost_router.message(Command("add_group"))
async def add_group_sechost_command(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool, is_superadmin: bool):
    if not is_admin or not is_superadmin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    mesg = await msg.answer(text.gen_wait)
    await state.set_state(GroupSechost_states.add_command)

    args = msg.text.split()[1:]

    # Инициализация переменных
    name = None
    description = None
    security_hosts = []

    # Парсинг аргументов
    for arg in args:
        if arg.startswith("description="):
            description = arg.split("=", 1)[1]
        elif not name:
            name = arg
        else:
            security_hosts.append(arg)

    # Проверка наличия обязательных параметров
    if not name or not security_hosts:
        await mesg.edit_text("Пожалуйста, укажите все параметры: [name] description=описание [имена или IP-адреса Security Hosts через пробел]")
        return

    # Создание или обновление записи
    result = await orm_query.create_or_update_group_security_host(
        session,
        name,
        description if description else "Нет описания",
        security_hosts
    )

    if result:
        await mesg.edit_text(f"Группа СЗИ '{name}' успешно добавлена или обновлена.", parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка создания/обновления группы СЗИ.")

    await state.set_state(Base_states.start)

@group_sechost_router.message(Command("delete_group"))
@flags.chat_action("typing")
async def process_delete_group_sechost_command(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession, is_admin: bool, is_superadmin: bool):
    if not is_admin or not is_superadmin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    await state.set_state(GroupSechost_states.delete_command)

    args = msg.text.split()[1:]

    if not args:
        await mesg.edit_text("Пожалуйста, введите имена групп СЗИ через пробел.")
        await state.set_state(Base_states.start)
        return

    error_names = []
    success_names = []

    for group_name in args:
        result = await orm_query.delete_group_security_host(session, group_name)
        if result:
            success_names.append(group_name)
        else:
            error_names.append(group_name)

    output = await format.delete_group_sechost_info(success_names, error_names)
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await state.set_state(Base_states.start)

@group_sechost_router.message(Command("view_group"))
async def view_group_sechost_command(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    mesg = await msg.answer(text.gen_wait)
    await state.set_state(GroupSechost_states.view_command)

    args = msg.text.split()[1:]

    if len(args) < 1:
        await mesg.edit_text("Пожалуйста, укажите количество и единицу времени (sec, min, hour, day, week) или 'all' для полного периода.")
        await state.set_state(Base_states.start)
        return

    # Проверяем ввод пользователя
    if args[0].lower() == "all":
        time_value = 'all'
        time_unit = None
        start_time = None
        end_time = None
    else:
        try:
            time_value = int(args[0])  # Первое значение - это число
            time_unit = args[1].lower() if len(args) > 1 else 'day'  # Второе значение - это единица времени (по умолчанию 'day')

            end_time = date_time.now()

            # Определяем временной промежуток на основе единицы времени
            if time_unit == "sec":
                start_time = end_time - datetime.timedelta(seconds=time_value)
            elif time_unit == "min":
                start_time = end_time - datetime.timedelta(minutes=time_value)
            elif time_unit == "hour":
                start_time = end_time - datetime.timedelta(hours=time_value)
            elif time_unit == "day":
                start_time = end_time - datetime.timedelta(days=time_value)
            elif time_unit == "week":
                start_time = end_time - datetime.timedelta(weeks=time_value)
            else:
                await mesg.edit_text("Вторая часть должна быть одной из следующих: sec, min, hour, day, week.")
                await state.set_state(Base_states.main_menu )
                return
        except (ValueError, IndexError):
            await mesg.edit_text("Ошибка: необходимо указать корректные параметры.")
            await state.set_state(Base_states.main_menu )
            return

    # Получаем данные из базы данных
    group_sechosts = await orm_query.get_group_security_hosts_within_timeframe(session, start_time, end_time)

    if group_sechosts:
        output = await format.group_sechost_info(group_sechosts, time_value, time_unit)
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Группы СЗИ не найдены.")

    # Возвращаемся к меню
    await state.set_state(Base_states.main_menu )
