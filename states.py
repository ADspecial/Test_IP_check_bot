# Classes for FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    start = State()
    about_ip = State()
    virustotal_menu = State()
    ipinfo_menu = State()
    about_ip_ipinfo = State()
    get_doc_ipinfo = State()
    check_ips = State()
    get_doc = State()
