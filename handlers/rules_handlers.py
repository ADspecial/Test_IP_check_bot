from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot, types
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Rules_states

from sqlalchemy.ext.asyncio import AsyncSession
from handlers import format
from database.models import TypeSechosts

import kb
import text
import database.orm_query as orm_query


rule_router = Router()

@rule_router.callback_query(F.data == "add_blockrules")
async def start_process_create_blockrule(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Rules_states.add_name_block)
    await clbck.message.edit_text("Введите имя правила:", reply_markup=kb.back_rule)


@rule_router.message(Rules_states.add_name_block)
async def process_name_blockrule(msg: Message, state: FSMContext, bot: Bot):
    #await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text.strip())
    await state.set_state(Rules_states.add_blocklist)
    await msg.answer("Введите имя ЧС:", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.add_blocklist)
async def process_blocklist_blockrule(msg: Message, state: FSMContext, bot: Bot):
   # await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(blocklist=msg.text.strip())
    await state.set_state(Rules_states.add_target_block)
    await msg.answer("Введите имя СУ или группы СУ:", reply_markup=kb.back_rule)


@rule_router.message(Rules_states.add_target_block)
@flags.chat_action("typing")
async def process_create_blockrule(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    #await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    mesg = await msg.answer("Пожалуйста, подождите...")

    data = await state.get_data()
    target = msg.text.strip()  # Просто записываем переданное значение

    # Создание нового правила
    try:
        result = await orm_query.create_or_update_blockrule(
            session,
            name=data['name'],
            commit=data.get('commit', False),  # commit по умолчанию False
            blocklist_name=data['blocklist'],
            target=target,  # Передаем как есть
            action=False  # Устанавливаем action в 'drop'
        )

        if result:
            await mesg.edit_text(
                f"Правило '{data['name']}' успешно добавлено с action 'drop'.",
                parse_mode=ParseMode.MARKDOWN
            )
            await mesg.answer("Выберите действие:", reply_markup=kb.repeat_add_blockrules)
        else:
            await mesg.edit_text(
                "Ошибка создания правила. Проверьте данные и повторите попытку.",
                reply_markup=kb.repeat_add_blockrules
            )
    except Exception as e:
        await mesg.edit_text(f"Ошибка при создании правила: {e}", reply_markup=kb.repeat_add_blockrules)

    await state.set_state(Base_states.start)

@rule_router.callback_query(F.data == "add_rules")
async def start_create_or_update_general_rule(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Rules_states.add_name)
    await clbck.message.edit_text("Введите имя правила:", reply_markup=kb.back_rule)


@rule_router.message(Rules_states.add_name)
async def process_general_rule_name(msg: Message, state: FSMContext, bot: Bot):
    #await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(name=msg.text.strip())
    await state.set_state(Rules_states.add_source)
    await msg.answer(
        "Введите source_ip и source_port в формате '192.168.1.1:22' или укажите BlockList name. "
        "Если порт не нужен, просто укажите IP:",
        reply_markup=kb.back_rule,
    )


@rule_router.message(Rules_states.add_source)
async def process_general_rule_source(msg: Message, state: FSMContext, bot: Bot):
   # await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(source=msg.text.strip())
    await state.set_state(Rules_states.add_destination)
    await msg.answer(
        "Введите destination_ip и destination_port в формате '192.168.1.1:22' или укажите BlockList name. "
        "Если порт не нужен, просто укажите IP:",
        reply_markup=kb.back_rule,
    )


@rule_router.message(Rules_states.add_destination)
async def process_general_rule_destination(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(destination=msg.text.strip())
    await state.set_state(Rules_states.add_protocol)
    await msg.answer(
        "Укажите протокол (TCP, UDP, TCP/UDP):",
        reply_markup=kb.back_rule,
    )


@rule_router.message(Rules_states.add_protocol)
async def process_general_rule_protocol(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    protocol = msg.text.strip().upper()
    if protocol not in ["TCP", "UDP", "TCP/UDP"]:
        await msg.answer("Некорректное значение. Укажите TCP, UDP или TCP/UDP:", reply_markup=kb.back_rule)
        return
    await state.update_data(protocol=protocol)
    await state.set_state(Rules_states.add_action)
    await msg.answer(
        "Укажите действие (pass или drop):",
        reply_markup=kb.back_rule,
    )


@rule_router.message(Rules_states.add_action)
async def process_general_rule_action(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    action = msg.text.strip().lower()
    if action not in ["pass", "drop"]:
        await msg.answer("Некорректное значение. Укажите pass или drop:", reply_markup=kb.back_rule)
        return
    await state.update_data(action=(action == "pass"))  # Преобразуем в bool
    await state.set_state(Rules_states.add_commit)
    await msg.answer(
        "Укажите commit (True или False):",
        reply_markup=kb.back_rule,
    )


@rule_router.message(Rules_states.add_commit)
@flags.chat_action("typing")
async def process_general_rule_commit(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    commit = msg.text.strip().lower()
    if commit not in ["true", "false"]:
        await msg.answer("Некорректное значение. Укажите True или False:", reply_markup=kb.back_rule)
        return

    data = await state.get_data()
    data["commit"] = commit == "true"

    mesg = await msg.answer("Пожалуйста, подождите...")

    try:
        # Вызов функции создания/обновления общего правила
        result = await orm_query.create_or_update_general_rule(
            session=session,
            name=data["name"],
            source=data["source"],
            destination=data["destination"],
            protocol=data["protocol"],
            action=data["action"],
            commit=data["commit"],
        )

        if result:
            await mesg.edit_text(
                f"Общее правило '{data['name']}' успешно создано или обновлено.",
                parse_mode=ParseMode.MARKDOWN,
            )
            await mesg.answer("Выберите действие:", reply_markup=kb.repeat_add_rules)
        else:
            await mesg.edit_text(
                "Ошибка создания/обновления общего правила. Проверьте данные и повторите попытку.",
                reply_markup=kb.repeat_add_rules,
            )
    except Exception as e:
        await mesg.edit_text(f"Ошибка при создании/обновлении общего правила: {e}", reply_markup=kb.repeat_add_rules)

    await state.set_state(Base_states.start)

@rule_router.callback_query(F.data == "delete_rules")
async def start_delete_rule(clbck: CallbackQuery, state: FSMContext):
    """
    Запускает процесс удаления правила.
    """
    await state.set_state(Rules_states.delete_name)
    await clbck.message.edit_text("Введите имя правила, которое вы хотите удалить:", reply_markup=kb.back_rule)


@rule_router.message(Rules_states.delete_name)
@flags.chat_action("typing")
async def process_delete_rule_name(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    """
    Обрабатывает ввод имени правила для удаления и вызывает функцию удаления.
    """
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    rule_name = msg.text.strip()

    mesg = await msg.answer("Пожалуйста, подождите...")

    try:
        # Вызов функции для удаления правила
        result = await orm_query.delete_rule(session=session, name=rule_name)

        if result:
            await mesg.edit_text(
                f"Правило '{rule_name}' успешно удалено.",
                parse_mode=ParseMode.MARKDOWN,
            )
            await mesg.answer("Выберите действие:", reply_markup=kb.repeat_delete_rules)
        else:
            await mesg.edit_text(
                f"Ошибка: Правило с именем '{rule_name}' не найдено.",
                reply_markup=kb.repeat_delete_rules,
            )
    except Exception as e:
        await mesg.edit_text(f"Ошибка при удалении правила: {e}", reply_markup=kb.repeat_delete_rules)

    await state.set_state(Base_states.start)

@rule_router.callback_query(F.data == "view_blockrules")
async def start_get_block_rules(clbck: CallbackQuery, state: FSMContext):
    """
    Запускает процесс получения записей из таблицы Rule с full=BLOCK.
    """
    await state.set_state(Rules_states.view_blockrules)
    await clbck.message.edit_text(
        "Введите количество дней от текущего момента для фильтрации записей или 'all' для получения всех записей:",
        reply_markup=kb.back_view_rules_menu,
    )

@rule_router.message(Rules_states.view_blockrules)
@flags.chat_action("typing")
async def process_get_block_rules_days(msg: Message, bot: Bot, session: AsyncSession, state: FSMContext):
    #await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    #await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    input_text = msg.text.strip()

    # Установка временного интервала
    if input_text.lower() == "all":
        start_time = None
        end_time = None
    else:
        try:
            days = int(input_text)
            end_time = date_time.now()
            start_time = end_time - datetime.timedelta(days=days)
        except ValueError:
            await msg.answer("Некорректный ввод. Укажите число дней или 'all':", reply_markup=kb.repeat_view_blockrules)
            return

    mesg = await msg.answer("Пожалуйста, подождите...")

    try:
        # Получение правил из базы данных
        block_rules = await orm_query.get_block_rules_within_timeframe(
            session=session,
            start_time=start_time,
            end_time=end_time,
        )

        # Форматирование текста
        formatted_text = await format.blockrules_info(
            block_rules,
            time=input_text if input_text.lower() != "all" else None,
            timeparam="дней" if input_text.lower() != "all" else "всего периода"
        )

        await mesg.edit_text(formatted_text, parse_mode="Markdown")
        await mesg.answer("Выберите действие:", reply_markup=kb.repeat_view_blockrules)
    except Exception as e:
        await mesg.edit_text(f"Ошибка при получении записей: {e}", reply_markup=kb.repeat_view_blockrules)

    await state.set_state(Base_states.start)

@rule_router.callback_query(F.data == "commit_rules")
async def start_process_create_blockrule(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Rules_states.add_name_block)
    await clbck.message.edit_text(text.commit_menu, reply_markup=kb.commit_menu)

# Обработчик для callback_data="commit_vipnet"
@rule_router.callback_query(F.data == "commit_vipnet")
async def handle_commit_vipnet(callback_query: types.CallbackQuery, session: AsyncSession):
    try:
        # Запрос в базу данных
        rules = await orm_query.get_uncommitted_rules(session, host_type=TypeSechosts.VIPNET)

        # Формирование сообщения
        if rules:
            message = "Правила с commit=False для VIPNET:\n" + "\n".join([rule['name'] for rule in rules])
        else:
            message = "Нет правил с commit=False для VIPNET."

        # Отправка ответа
        await callback_query.message.answer(message)
    except Exception as e:
        await callback_query.message.answer(f"Произошла ошибка: {e}")

# Обработчик для callback_data="commit_usergate"
@rule_router.callback_query(F.data == "commit_usergate")
async def handle_commit_usergate(callback_query: types.CallbackQuery, session: AsyncSession):
    try:
        # Запрос в базу данных
        rules = await orm_query.get_uncommitted_rules(session, host_type=TypeSechosts.USERGATE)

        # Формирование сообщения
        if rules:
            message = "Правила с commit=False для UserGate:\n" + "\n".join([rule['name'] for rule in rules])
        else:
            message = "Нет правил с commit=False для UserGate."

        # Отправка ответа
        await callback_query.message.answer(message)
    except Exception as e:
        await callback_query.message.answer(f"Произошла ошибка: {e}")

# Обработчик для callback_data="get_status"
@rule_router.callback_query(F.data == "get_status")
async def handle_get_status(callback_query: types.CallbackQuery, session: AsyncSession):
    try:
        # Запрос в базу данных
        rules = await orm_query.get_rules_with_false_status(session)

        # Формирование сообщения
        if rules:
            message = "Правила со статусом False:\n" + "\n".join([rule['name'] for rule in rules])
        else:
            message = "Нет правил со статусом False."

        # Отправка ответа
        await callback_query.message.answer(message)
    except Exception as e:
        await callback_query.message.answer(f"Произошла ошибка: {e}")
