# Вспомогательные классы для FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    start = State()
    about_ip = State()
    check_ips = State()
    get_doc = State()
