# Entry point
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.client.bot import DefaultBotProperties
from aiogram.utils.chat_action import ChatActionMiddleware

from database.engine import create_db, drop_db, session_maker
from config.config import KEYS
from handlers import router
from middleware.db import DataBaseSession
from middleware.logs import LogMessageMiddleware

async def on_startup(bot):
    run_param = False
    if run_param:
        await drop_db()
    await create_db()

async def on_shutdown(bot):
    print('bot shutdown')

async def main():
    bot = Bot(token=KEYS.TG_KEY, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    dp.update.middleware(DataBaseSession(session_pool=session_maker))
    dp.message.middleware(ChatActionMiddleware())
    router.message.outer_middleware(LogMessageMiddleware(session_pool=session_maker))
    dp.include_router(router)

    await bot.delete_webhook(drop_pending_updates=True)

    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot exit!")
