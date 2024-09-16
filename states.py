# Classes for FSM

from aiogram.fsm.state import StatesGroup, State

class Gen(StatesGroup):
    start = State()
    main_menu = State()
    check_menu = State()
    virustotal_menu = State()
    ipinfo_menu = State()
    help = State()
    get_doc = State()
    vt_ip = State()
    vt_list = State()
    vt_file = State()
    vt_file_command = State()
    ipi_ip = State()
    ipi_file = State()
