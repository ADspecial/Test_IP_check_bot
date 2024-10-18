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
    alienvault_menu = State()
    ipqualityscore_menu = State()
    summary_menu = State()
    admin_menu = State()
    block_menu = State()
    help = State()

class Block_states(StatesGroup):
    blocklist_menu = State()
    blocklist_add_name = State()
    blocklist_add_description = State()
    blocklist_add = State()
    blocklist_add_command = State()
    blocklist_view = State()
    blocklist_view_command = State()
    blocklist_delete = State()
    blocklist_delete_command = State()


class Admin_states(StatesGroup):
    users_menu = State()
    add_admin = State()

class Summary_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

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

class ALV_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()

class IPQS_states(StatesGroup):
    menu = State()
    get_doc = State()
    check_ip = State()
    check_ip_file = State()
    check_ip_file_command = State()
