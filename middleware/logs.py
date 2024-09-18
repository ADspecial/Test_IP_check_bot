from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
from database.models import History

class LogMessageMiddleware(BaseMiddleware):
    def __init__(self, session_pool: async_sessionmaker):
        super().__init__()
        self.session_pool = session_pool
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        if isinstance(event, Message):
            await self.save_message(event, data['session'])
        return await handler(event, data)

    async def save_message(self, msg: Message, session):
        chat_message = History(
            user_id=str(msg.from_user.id),
            chat_id=str(msg.chat.id),
            message=msg.text
        )
        session.add(chat_message)
        await session.commit()
