# Classes for FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    start = State()
    main_menu = State()
    check_menu = State()
    virustotal_menu = State()
    help = State()

    about_ip = State()
    ipinfo_menu = State()
    about_ip_ipinfo = State()
    get_doc_ipinfo = State()
    check_ips = State()
    get_doc = State()
