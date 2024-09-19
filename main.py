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

from middleware.db import DataBaseSession
from middleware.logs import LogMessageMiddleware

async def on_startup(bot):
    run_param = False
    if run_param:
        await drop_db()
    await create_db()

async def on_shutdown(bot):
    print('bot shutdown')

async def main() -> None:
    """Main entry point for the bot."""
    bot = Bot(token=KEYS.TG_KEY, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    dp.message.middleware(DataBaseSession(session_pool=session_maker))
    dp.message.middleware(ChatActionMiddleware())
    dp.message.middleware(LogMessageMiddleware(session_pool=session_maker))

    dp.include_router(ipi_router)
    dp.include_router(menu_router)
    dp.include_router(vt_router)

    await bot.delete_webhook(drop_pending_updates=True)

    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types(), fast=True)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot exit!")
