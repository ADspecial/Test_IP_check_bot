# Вспомогательные классы для FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    about_ip = State()
    check_ips = State()
