from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext


from states import Base_states, KSP_states

from ipcheckers import kaspersky

from handlers import process

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import re
import text
import database.orm_query as orm_query

rules_router = Router()

from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Rules_states

from sqlalchemy.ext.asyncio import AsyncSession

import kb
import text
import database.orm_query as orm_query

rule_router = Router()

@rule_router.callback_query(F.data == "add_rules")
async def start_process_create_rule(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Rules_states.add_name)
    await clbck.message.edit_text("Введите имя правила:", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.add_name)
async def process_name_rule(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Rules_states.add_commit)
    await msg.answer("Укажите значение commit (True/False):", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.add_commit)
async def process_commit_rule(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    commit_value = msg.text.lower()
    if commit_value not in ["true", "false"]:
        await msg.answer("Некорректное значение. Укажите True или False:", reply_markup=kb.back_rule)
        return

    await state.update_data(commit=(commit_value == "true"))
    await state.set_state(Rules_states.add_blocklist)
    await msg.answer("Введите имя BlockList:", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.add_blocklist)
async def process_blocklist_rule(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    await state.update_data(blocklist=msg.text)
    await state.set_state(Rules_states.add_target)
    await msg.answer("Введите имя SecurityHost или GroupSecurityHost (опционально):", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.add_target)
@flags.chat_action("typing")
async def process_create_rule(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    mesg = await msg.answer(text.gen_wait)

    data = await state.get_data()
    security_host_name = None
    group_security_host_name = None

    # Определяем, указал ли пользователь SecurityHost или GroupSecurityHost
    if msg.text:
        if "group_" in msg.text.lower():
            group_security_host_name = msg.text
        else:
            security_host_name = msg.text

    # Создание или обновление правила
    result = await orm_query.create_or_update_rule(
        session,
        name=data['name'],
        commit=data['commit'],
        blocklist_name=data['blocklist'],
        security_host_name=security_host_name,
        group_security_host_name=group_security_host_name
    )

    if result:
        await mesg.edit_text(f"Правило '{data['name']}' успешно добавлено или обновлено.", parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка создания/обновления правила.")

    await state.set_state(Base_states.start)

@rule_router.callback_query(F.data == "update_commit_rule")
async def start_process_update_commit_rule(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Rules_states.update_name)
    await clbck.message.edit_text("Введите имя правила для обновления commit:", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.update_name)
async def process_update_name_rule(msg: Message, state: FSMContext, bot: Bot):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    await state.update_data(name=msg.text)
    await state.set_state(Rules_states.update_commit)
    await msg.answer("Укажите новое значение commit (True/False):", reply_markup=kb.back_rule)

@rule_router.message(Rules_states.update_commit)
@flags.chat_action("typing")
async def process_update_commit_rule(msg: Message, bot: Bot, state: FSMContext, session: AsyncSession):
    await bot.delete_message(msg.chat.id, msg.message_id-1, request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id, request_timeout=0)
    mesg = await msg.answer(text.gen_wait)

    commit_value = msg.text.lower()
    if commit_value not in ["true", "false"]:
        await mesg.edit_text("Некорректное значение. Укажите True или False:")
        return

    data = await state.get_data()
    result = await orm_query.update_rule_commit(
        session,
        rule_name=data['name'],
        new_commit=(commit_value == "true")
    )

    if result:
        await mesg.edit_text(f"Флаг commit для правила '{data['name']}' успешно обновлен.", parse_mode=ParseMode.MARKDOWN)
    else:
        await mesg.edit_text("Ошибка обновления флага commit для правила.")

    await state.set_state(Base_states.start)
