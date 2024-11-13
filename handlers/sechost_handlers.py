from datetime import datetime as date_time
import datetime
from aiogram import F, Router, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode

from states import Base_states, Sechost_states

from ipcheckers.valid_ip import extract_and_validate, is_valid_ip

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
    await bot.delete_message(msg.chat.id, msg.message_id-1,request_timeout=0)
    await bot.delete_message(msg.chat.id, msg.message_id,request_timeout=0)
    await state.update_data(ip=msg.text)
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
    data = await state.get_data()
    apitoken = msg.text
    result = await orm_query.create_or_update_security_host(session, data['name'], data['description'], data['ip'], apitoken, data['login'], data['password'])
    if result == 1:
        output = await format.sechost_output([data['name'],  data['ip']])
        await mesg.edit_text(output, parse_mode=ParseMode.MARKDOWN)
        await mesg.answer("Выберете действие:", reply_markup=kb.repeat_add_sechost)
    else:
        await mesg.edit_text("Ошибка создания/обновления блоклиста", reply_markup=kb.repeat_add_sechost)
