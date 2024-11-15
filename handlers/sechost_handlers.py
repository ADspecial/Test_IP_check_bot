from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Sechost_states

from ipcheckers.valid_ip import is_valid_ip

from handlers import format

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import text
import database.orm_query as orm_query

sechost_router = Router()

@sechost_router.callback_query(F.data == "add_sechost")
async def start_process_create_sechost(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Sechost_states.add_name)
    await clbck.message.edit_text("Введите имя СЗИ:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_name)
async def process_name_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Sechost_states.add_description)
    await msg.answer("Введите описание:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_description)
async def process_description_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(description=msg.text)
    await state.set_state(Sechost_states.add_ip)
    await msg.answer("Введите ip адрес доступа к СЗИ:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_ip)
async def process_ip_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id - 1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)

    ip_address = msg.text

    if not is_valid_ip(ip_address):
        await msg.answer("Неверный IP-адрес. Пожалуйста, введите корректный IP-адрес:", reply_markup=kb.back_sechost)
        return

    await state.update_data(ip=ip_address)
    await state.set_state(Sechost_states.add_login)
    await msg.answer("Введите логин СЗИ:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_login)
async def process_login_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(login=msg.text)
    await state.set_state(Sechost_states.add_password)
    await msg.answer("Введите пароль СЗИ:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.add_password)
async def process_login_sechost(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(password=msg.text)
    await state.set_state(Sechost_states.add)
    await msg.answer("Введите api_token СЗИ (если есть):", reply_markup=kb.back_sechost)


@sechost_router.message(Sechost_states.add)
@flags.chat_action("typing")
async def process_create_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    await state.update_data(api_token=msg.text)
    data = await state.get_data()
    result = await orm_query.create_or_update_security_host(session, data['name'], data['description'], data['ip'], data['api_token'], data['login'], data['password'])
    if result == 1:
        output = await format.sechost_output([data['name'],  data['ip']])
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer("Выберете действие:", reply_markup=kb.repeat_add_sechost)
    else:
        await mesg.edit_text("Ошибка создания/обновления блоклиста", reply_markup=kb.repeat_add_sechost)

@sechost_router.message(Command("add_host"))
async def add_sechost_command(msg: Message, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    mesg = await msg.answer(text.gen_wait)
    await state.set_state(Sechost_states.add_command)

    args = msg.text.split()[1:]

    # Проверка наличия обязательных параметров
    if len(args) < 4:
        await mesg.edit_text("Пожалуйста, укажите все параметры: [name] [ip] [login=login] [password=pass] [api_token=token (необязательно)] [description (необязательно)]")
        return

    name = args[0]
    ip = args[1]

    # Инициализация переменных
    login = None
    password = None
    api_token = None
    description = 'None'

    for arg in args[2:]:
        if arg.startswith("login="):
            login = arg.split("=", 1)[1]  # Извлекаем значение после '='
        elif arg.startswith("password="):
            password = arg.split("=", 1)[1]
        elif arg.startswith("api_token="):
            api_token = arg.split("=", 1)[1]
        else:
            description += f" {arg}"  # Сохраняем остальные аргументы как описание

    # Проверка на наличие обязательных аргументов
    if login is None or password is None:
        await mesg.edit_text("Ошибка: необходимо указать оба аргумента: login и password в формате login=значение и password=значение.")
        await state.set_state(Base_states.start)
        return

    # Проверка валидности IP-адреса
    if not is_valid_ip(ip):
        await mesg.edit_text(f"Некорректный IP-адрес: {ip}. Пожалуйста, проверьте ввод.")
        await state.set_state(Base_states.start)
        return

    # Установка значений по умолчанию для необязательных аргументов
    api_token = api_token if api_token else 'None'

    # Создание или обновление записи
    result = await orm_query.create_or_update_security_host(
        session,
        name,
        description.strip(),  # Удаляем лишние пробелы
        ip,
        api_token,
        login,
        password
    )

    if result:
        await mesg.edit_text(f"СЗИ '{name}' успешно добавлен или обновлен.", parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка создания/обновления СЗИ.")

    await state.set_state(Base_states.start)

@sechost_router.callback_query(F.data == "delete_sechost")
async def start_process_delete_sechost(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Sechost_states.delete)
    await clbck.message.edit_text("Введите имена или IP-адреса СЗИ через пробел:", reply_markup=kb.back_sechost)

@sechost_router.message(Sechost_states.delete)
@flags.chat_action("typing")
async def process_create_blocklist(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    identifiers = msg.text.strip().split()
    mesg = await msg.answer(text.gen_wait)
    error = []
    success = []
    for identifier in identifiers:
        result = await orm_query.delete_security_host(session, str(identifier))
        if result:
            success.append(identifier)
        else:
            error.append(identifier)

    output = await format.delete_sechost_info(success, error)
    # Отправляем ответ
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await mesg.answer("Выберете действие:", reply_markup=kb.repeat_delete_sechost)

@sechost_router.message(Command("delete_host"))
@flags.chat_action("typing")
async def process_delete_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession, is_admin: bool):
    if not is_admin:
        await msg.answer(text.false_admin.format(name=msg.from_user.full_name))
        return

    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer(text.gen_wait)
    await state.set_state(Sechost_states.delete_command)

    args = msg.text.split()[1:]

    if not args:
        await mesg.edit_text("Пожалуйста, введите имена или IP-адреса СЗИ через пробел.")
        await state.set_state(Base_states.start)
        return

    error_names = []
    success_names = []

    for identifier in args:
        result = await orm_query.delete_security_host(session, str(identifier))
        if result:
            success_names.append(identifier)
        else:
            error_names.append(identifier)

    output = await format.delete_sechost_info(success_names, error_names)
    await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
    await state.set_state(Base_states.start)

@sechost_router.callback_query(F.data == "view_sechost")
async def start_process_view_sechost(clbck: CallbackQuery, state: FSMContext):
    await clbck.message.edit_text("Введите all или количество дней за которое необходимо просмотреть СЗИ:",reply_markup=kb.back_sechost)
    await state.set_state(Sechost_states.view)

@sechost_router.message(Sechost_states.view)
@flags.chat_action("typing")
async def view_sechost(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    # Проверяем ввод пользователя
    if msg.text.lower() == "all":
        start_time = None
        end_time = None
        days_text = "всего периода"
    else:
        try:
            day = int(msg.text)
            end_time = datetime.now()
            start_time = end_time - datetime.timedelta(days=day)
            days_text = f"последние {day} дней"
        except ValueError:
            # Если введено не число и не "all", выводим сообщение об ошибке
            await msg.answer("Количество дней должно быть числом или 'all' для полного периода", reply_markup=kb.repeat_view_blocklist)
            await state.set_state(Sechost_states.menu)
            return

    # Удаляем сообщения
    await bot.delete_message(msg.chat.id, msg.message_id-2, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)

    # Отправляем сообщение о начале обработки
    mesg = await msg.answer(text.gen_wait)

    # Получаем данные из базы данных
    sechosts = await orm_query.get_security_hosts_within_timeframe(session, start_time, end_time)

    if sechosts:
        # Форматируем и отправляем информацию о найденных записях
        output = await format.sechost_info(sechosts, days_text, 'day')
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await msg.answer("Выберите действие:", reply_markup=kb.repeat_view_sechost)
    else:
        await mesg.edit_text("СЗИ не найдены", reply_markup=kb.repeat_view_sechost)

    # Возвращаемся к меню
    await state.set_state(Sechost_states.menu)
