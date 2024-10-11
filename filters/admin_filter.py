from typing import Union
from aiogram.filters import BaseFilter
from aiogram.types import Message
from sqlalchemy.ext.asyncio import AsyncSession

from database import orm_query  # Импортируйте вашу функцию проверки прав администратора
from database.models import User  # Импортируйте модель User

class AdminRightsFilter(BaseFilter):
    def __init__(self, user_id: int):  # [1]
        self.user_id = user_id

    async def __call__(self, message: Message) -> bool:  # [2]
        async with AsyncSession() as session:
            # Проверяем права администратора для данного пользователя
            is_admin = await orm_query.check_admin_rights(session, self.user_id)
            return is_admin
