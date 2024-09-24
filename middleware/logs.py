from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware, Bot
from aiogram.types import Message, TelegramObject
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
from database.models import History, User
from sqlalchemy.future import select

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
        user_id = msg.from_user.id
        result = await session.execute(select(User).filter_by(id=str(user_id)))
        user = result.scalars().first()
        if not user:
            user = User(
                id=str(user_id),
                first_name=msg.from_user.first_name,
                last_name=msg.from_user.last_name,
                username=msg.from_user.username,
            )
            session.add(user)
            await session.commit()

        chat_message = History(
            user_id=str(msg.from_user.id),
            chat_id=str(msg.chat.id),
            message_id=str(msg.message_id),
            message=msg.text
        )
        session.add(chat_message)
        await session.commit()
