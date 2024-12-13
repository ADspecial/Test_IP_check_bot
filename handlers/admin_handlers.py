from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.types import FSInputFile
from typing import List, Dict
import datetime
from datetime import datetime


from states import Base_states, Admin_states

from ipcheckers import alienvault

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

from filters.chat_type import ChatTypeFilter

from graphs.create_graps import create_user_distribution_chart

import kb
import os
import re
import json
import text
import database.orm_query as orm_query

admin_router = Router()
admin_router.message.filter(ChatTypeFilter(chat_type=["private"]))

@admin_router.message(Command("admin"))
async def start_admin_menu_handler(msg: Message, state: FSMContext, is_superadmin: bool):
    if is_superadmin:
        await state.set_state(Base_states.admin_menu)
        await msg.answer(text.start_admin_menu.format(name=msg.from_user.full_name), reply_markup=kb.admin_menu)
    else:
        await msg.answer(text.false_admin_menu.format(name=msg.from_user.full_name))

@admin_router.callback_query(F.data == "admin_menu")
async def admin_menu_handler(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Base_states.admin_menu)
    await clbck.message.edit_text(text.admin_menu, reply_markup=kb.admin_menu)

@admin_router.callback_query(F.data == "users_menu")
async def users_menu(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Admin_states.users_menu)
    await msg_or_callback.message.edit_text(text.users_menu, reply_markup=kb.users_menu)

@admin_router.callback_query(F.data == "add_admin")
async def add_admin_handler(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Admin_states.add_admin)
    await clbck.message.edit_text(text.about_add_admin, reply_markup=kb.back_users)

@admin_router.message(Admin_states.add_admin)
@flags.chat_action("typing")
async def add_admin(msg: Message, is_admin: bool, session: AsyncSession):
    if is_admin:
        username = msg.text.strip()
        try:
            result = await orm_query.grant_admin_rights(session, username)
            if result:
                await msg.answer(text.success_add_admin.format(username=username), reply_markup=kb.back_users)
            else:
                await msg.answer(text.err_add_admin.format(username=username), reply_markup=kb.back_users)
        except Exception as e:
            print(f"Ошибка при добавлении прав администратора: {e}")
            await msg.answer("Произошла ошибка при обработке запроса.", reply_markup=kb.back_users)

@admin_router.callback_query(F.data == "report_menu")
async def report_menu(msg_or_callback: Message | CallbackQuery, state: FSMContext):
    await state.set_state(Admin_states.report_menu)
    await msg_or_callback.message.edit_text(text.report_menu, reply_markup=kb.report_menu)

@admin_router.callback_query(F.data == "report_users")
async def report_users_handler(callback_query: CallbackQuery, session: AsyncSession):
    """
    Обработчик для создания и отправки диаграммы распределения пользователей.
    """
    try:
        # Получаем статистику пользователей из базы данных
        result, statistics_json = await orm_query.get_user_statistics(session)
        if not result:
            await callback_query.message.answer("Ошибка при получении данных о пользователях.")
            return

        # Преобразуем статистику в словарь
        statistics = json.loads(statistics_json)

        # Генерация диаграммы
        chart_path = create_user_distribution_chart(statistics)
        if not chart_path:
            await callback_query.message.answer("Не удалось создать диаграмму.")
            return

        # Отправляем диаграмму с помощью FSInputFile
        photo = FSInputFile(chart_path)
        await callback_query.message.answer_photo(
            photo=photo,
            caption="Распределение пользователей."
        )
    except Exception as e:
        print(f"Ошибка в обработчике report_users_handler: {e}")
        await callback_query.message.answer("Произошла ошибка при обработке запроса.")

@admin_router.callback_query(F.data == "report_history")
async def report_history_handler(callback_query: CallbackQuery, session: AsyncSession):
    """
    Обработчик для получения и отправки истории команд в текстовом файле.
    """
    try:
        # Получение истории команд
        history: List[Dict[str, any]] = await orm_query.get_command_history(session)

        if not history:
            await callback_query.message.answer("История команд пуста.")
            return

        # Формируем путь к файлу
        output_dir = "./data/Reports"
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, f"command_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

        # Создаем текстовый файл с историей команд
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write("№ Пользователь Права Чат ID Сообщение Создано\n")
            file.write("=" * 80 + "\n")
            for idx, record in enumerate(history, start=1):
                file.write(
                    f"{idx} {record['username']} {record['role']} {record['chat_id']} "
                    f"{record['message']} {record['created']}\n"
                )

        # Отправка файла
        document = FSInputFile(file_path)
        await callback_query.message.answer_document(
            document=document,
            caption="История команд в текстовом файле."
        )
    except Exception as e:
        print(f"Ошибка в обработчике report_history_handler: {e}")
        await callback_query.message.answer("Произошла ошибка при обработке запроса.")
