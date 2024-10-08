# Classes for FSM

from aiogram.fsm.state import StatesGroup, State

class Base_states(StatesGroup):
    start = State()
    main_menu = State()
    check_menu = State()
    virustotal_menu = State()
    ipinfo_menu = State()
    adbuseip_menu = State()
    kaspersky_menu = State()
    criminalip_menu = State()
    help = State()

class VT_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

class IPI_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

class ADB_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

class KSP_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

class CIP_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()
