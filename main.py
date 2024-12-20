# Entry point

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.client.bot import DefaultBotProperties
from aiogram.utils.chat_action import ChatActionMiddleware

from config.config import KEYS
from database.engine import create_db, drop_db, session_maker

from handlers.menu_handlers import menu_router
from handlers.vt_handlers import vt_router
from handlers.ipi_handlers import ipi_router
from handlers.adb_handlers import adb_router
from handlers.ksp_handlers import ksp_router
from handlers.cip_handlers import cip_router
from handlers.alv_handlers import alv_router
from handlers.ipqs_handlers import ipqs_router
from handlers.admin_handlers import admin_router
from handlers.summary_handlers import sum_router
from handlers.blocklist_handlers import blocklist_router
from handlers.sechost_handlers import sechost_router
from handlers.group_sechost_handlers import group_sechost_router
from handlers.rules_handlers import rule_router

from command_hints import set_bot_commands

from middleware.db import DataBaseSession
from middleware.logs import LogMessageMiddleware
from middleware.admin_right import AdminRightsMiddleware

async def on_startup(bot):
    run_param = False
    if run_param:
        await drop_db()
    await create_db()

async def on_shutdown(bot):
    print('bot shutdown')

def register_routers(dp: Dispatcher):
    dp.include_router(ipi_router)
    dp.include_router(menu_router)
    dp.include_router(vt_router)
    dp.include_router(adb_router)
    dp.include_router(ksp_router)
    #dp.include_router(cip_router)
    dp.include_router(alv_router)
    dp.include_router(ipqs_router)
    dp.include_router(admin_router)
    dp.include_router(sum_router)
    dp.include_router(blocklist_router)
    dp.include_router(sechost_router)
    dp.include_router(group_sechost_router)
    dp.include_router(rule_router)

async def main() -> None:
    """Main entry point for the bot."""
    async with Bot(token=KEYS.TG_KEY, default=DefaultBotProperties(parse_mode=ParseMode.HTML)) as bot:
        dp = Dispatcher(storage=MemoryStorage())
        dp.startup.register(on_startup)
        dp.shutdown.register(on_shutdown)
        #dp.message.middleware(DataBaseSession(session_pool=session_maker))
        dp.update.middleware(DataBaseSession(session_pool=session_maker))
        dp.message.middleware(ChatActionMiddleware())
        dp.message.middleware(LogMessageMiddleware(session_pool=session_maker))
        dp.message.middleware(AdminRightsMiddleware(session_maker))
        dp.callback_query.middleware(AdminRightsMiddleware(session_maker))

        await set_bot_commands(bot)

        register_routers(dp)

        await bot.delete_webhook(drop_pending_updates=True)

        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types(), fast=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot exit!")
#
