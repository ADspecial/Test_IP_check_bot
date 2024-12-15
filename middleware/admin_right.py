from typing import Callable, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import Message
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any, Awaitable, Callable, Dict
from aiogram.types import Message, TelegramObject, CallbackQuery
from sqlalchemy.ext.asyncio import async_sessionmaker

from database import orm_query

class AdminRightsMiddleware(BaseMiddleware):
    def __init__(self, session_pool: async_sessionmaker):
        self.session_pool = session_pool
        super().__init__()

    async def __call__(
        self,
        handler: Callable[[Message | CallbackQuery, Dict[str, Any]], Awaitable[Any]],
        event: Message | CallbackQuery,
        data: Dict[str, Any],
    ) -> Any:
        if isinstance(event, (Message, CallbackQuery)):
            async with self.session_pool() as session:
                await self.check_admin_rights(event, data, session)
        return await handler(event, data)

    async def check_admin_rights(self, event: Message | CallbackQuery, data: dict, session: AsyncSession) -> None:
        user_id = event.from_user.id
        is_admin, is_superadmin = await orm_query.check_admin_rights(session, user_id)

        data['is_superadmin'] = is_superadmin
        data['is_admin'] = is_admin
