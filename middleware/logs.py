from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject
from sqlalchemy.ext.asyncio import async_sessionmaker
from database.models import History, User
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from states import Sechost_states
from aiogram.fsm.context import FSMContext

import re

def sanitize_message(text: str) -> str:
    if not text:
        return ""
    login_pattern = re.compile(r"(?<=\blogin=)[^\s]+", re.IGNORECASE)
    password_pattern = re.compile(r"(?<=\bpassword=)[^\s]+", re.IGNORECASE)
    api_token_pattern = re.compile(r"(?<=\bapi_token=)[^\s]+", re.IGNORECASE)

    text = login_pattern.sub("[REDACTED]", text)
    text = password_pattern.sub("[REDACTED]", text)
    text = api_token_pattern.sub("[REDACTED]", text)

    return text

class LogMessageMiddleware(BaseMiddleware):
    sensitive_states = {
        Sechost_states.add_login,
        Sechost_states.add_password,
        Sechost_states.add  # Добавьте состояния, связанные с вводом данных
    }
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
            fsm_context = data.get('state')
            await self.save_message(event, fsm_context)
        return await handler(event, data)

    async def save_message(self, msg: Message, fsm_context: FSMContext):
        current_state = await fsm_context.get_state()

        if current_state in self.sensitive_states:
            return

        user_id = msg.from_user.id
        sanitized_text = sanitize_message(msg.text) if msg.text else None

        async with self.session_pool() as session:
            result = await session.execute(select(User).filter_by(id=user_id))
            user = result.scalars().first()

            if not user:
                user = User(
                    id=user_id,
                    first_name=msg.from_user.first_name,
                    last_name=msg.from_user.last_name,
                    username=msg.from_user.username,
                    superadmin_rights=False,
                    admin_rights=False
                )
                session.add(user)
                await session.commit()

            chat_message = History(
                message_id=msg.message_id,
                user_id=msg.from_user.id,
                chat_id=msg.chat.id,
                message=sanitized_text  # Сохраняем очищенный текст или None
            )
            session.add(chat_message)
        await session.commit()
