# Вспомогательные классы для FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    check_ip = State()
    img_prompt = State()
