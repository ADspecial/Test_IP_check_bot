from aiogram import F, Router, Bot
from aiogram.types import Message, CallbackQuery
from aiogram import flags
from aiogram.fsm.context import FSMContext

from states import Gen
from ipcheckers.ipinfo import get_info

from handlers.support import process_ip


import kb
import text


ipi_router = Router()

# Обработчик для вывода инфы об ip по ipinfo
@ipi_router.callback_query(F.data == "ipi_ip")
async def input_about_ip(clbck: CallbackQuery, state: FSMContext):
    await state.set_state(Gen.ipi_ip)
    await clbck.message.edit_text(text.about_check_ip,reply_markup=kb.back_vt)
    await state.update_data(last_message_id=clbck.message.message_id)

@ipi_router.message(Gen.ipi_ip)
@flags.chat_action("typing")
async def check_single_ip(msg: Message, bot: Bot, state: FSMContext):
    await process_ip(msg, get_info, text.err_ip, text.about_check_ip, kb.back_vt)
