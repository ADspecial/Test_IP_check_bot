# Функции-обработчики бота
from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext
from includes.single_ip import ip_info
import utils
from states import Gen
import re

import kb
import text

router = Router()

@router.message(Command("start"))
async def start_handler(msg: Message):
    await msg.answer(text.greet.format(name=msg.from_user.full_name), reply_markup=kb.menu)

@router.message(F.text == "Меню")
@router.message(F.text == "Выйти в меню")
@router.message(F.text == "◀️ Выйти в меню")
async def menu(msg: Message):
    await msg.answer(text.menu, reply_markup=kb.menu)

@router.callback_query(F.data == "check_ip")
async def input_check_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.check_ip)
    await clbck.message.edit_text(text.check_ip)
    await clbck.message.answer(text.gen_exit, reply_markup=kb.iexit_kb)

@router.message(Gen.check_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, state: FSMContext):
    ip = msg.text
    mesg = await msg.answer(text.gen_wait)
    res = ip_info(ip)
    if not res:
        return await mesg.edit_text(text.err_ip, reply_markup=kb.iexit_kb)
    str1 = '\n'.join(res)
    mal_str = res[12][12:]
    mal = int(mal_str)
    if int(mal) > 0:
        await mesg.edit_text(f"❌ - выявлены заражения от {mal} баз \n" + str1)
    else:
        await mesg.edit_text("✅ - заражения не выявлены \n" + str1)

'''
test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
