from typing import Callable, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import Message
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any, Awaitable, Callable, Dict
from aiogram.types import Message, TelegramObject

from database import orm_query

class AdminRightsMiddleware(BaseMiddleware):
    def __init__(self, session: AsyncSession):
        super().__init__()
        self.session = session

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        if isinstance(event, Message):
            await self.on_pre_process_message(event, data, data['session'])
        return await handler(event, data)
    async def on_pre_process_message(self, message: Message, data: dict, session) -> None:
        is_admin = await orm_query.check_admin_rights(session, message.from_user.id)

        data['is_admin'] = is_admin
