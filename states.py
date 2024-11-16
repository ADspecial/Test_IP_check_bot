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

class Blocklist_states(StatesGroup):
    menu = State()
    add_name = State()
    add_description = State()
    add = State()
    add_command = State()
    view = State()
    view_command = State()
    delete = State()
    delete_command = State()


class Sechost_states(StatesGroup):
    menu = State()
    add_name = State()
    add_description = State()
    add = State()
    add_command = State()
    view = State()
    view_command = State()
    delete = State()
    delete_command = State()

    add_ip = State()
    add_login = State()
    add_password = State()
    add_apitoken = State()

class GroupSechost_states(StatesGroup):
    menu = State()
    add_name = State()
    add_description = State()
    add = State()
    add_command = State()
    view = State()
    view_command = State()
    delete = State()
    delete_command = State()

    add_security_hosts = State()


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
