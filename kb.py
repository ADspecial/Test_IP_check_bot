# Bot keyboards

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove

start_menu = [
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
start_menu = InlineKeyboardMarkup(inline_keyboard=start_menu)

main_menu = [
    #[InlineKeyboardButton(text="🚫 Блокировка IP", callback_data="block_menu")],
    [InlineKeyboardButton(text="📄 Проверка адресов", callback_data="check_menu")],
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
main_menu = InlineKeyboardMarkup(inline_keyboard=main_menu)

main_menu_admin = [
    [InlineKeyboardButton(text="🚫 Блокировка адресов", callback_data="block_menu")],
    [InlineKeyboardButton(text="📄 Проверка адресов", callback_data="check_menu")],
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
main_menu_admin = InlineKeyboardMarkup(inline_keyboard=main_menu_admin)

block_menu = [
    [InlineKeyboardButton(text="📄 Управлние черными списками", callback_data="blocklist_menu"),
    InlineKeyboardButton(text="🌐 Управление сетевыми устройствами", callback_data="sechost_menu")],
    [InlineKeyboardButton(text="🚫 Управление правилами", callback_data="rules_menu")],
    [InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]
]
block_menu = InlineKeyboardMarkup(inline_keyboard=block_menu)

blocklist_menu = [
    [InlineKeyboardButton(text="✍️ Создать/изменить ЧС", callback_data="add_bloсklist")],
    [InlineKeyboardButton(text="🗑 Удалить ЧС", callback_data="delete_bloсklist"),
    InlineKeyboardButton(text="📄 Просмотр ЧС", callback_data="view_bloсklist")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="block_menu")]
]
blocklist_menu = InlineKeyboardMarkup(inline_keyboard=blocklist_menu)

repeat_add_blocklist = [
    [InlineKeyboardButton(text="Добавить еще ЧС", callback_data="add_bloсklist")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="blocklist_menu")]
]
repeat_add_blocklist = InlineKeyboardMarkup(inline_keyboard=repeat_add_blocklist)

repeat_view_blocklist = [
    [InlineKeyboardButton(text="Просмотреть за другую дату", callback_data="view_bloсklist")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="blocklist_menu")]
]
repeat_view_blocklist = InlineKeyboardMarkup(inline_keyboard=repeat_view_blocklist)

repeat_delete_blocklist = [
    [InlineKeyboardButton(text="Удалить другие ЧС", callback_data="delete_bloсklist")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="blocklist_menu")]
]
repeat_delete_blocklist = InlineKeyboardMarkup(inline_keyboard=repeat_delete_blocklist)

sechost_menu = [
    [InlineKeyboardButton(text="✍️ Создать/изменить СУ", callback_data="add_sechost")], [InlineKeyboardButton(text="🗑 Удалить СЗИ", callback_data="delete_sechost"),
    InlineKeyboardButton(text="📄 Просмотр СУ", callback_data="view_sechost")],
    [InlineKeyboardButton(text="📑 Управление группами СУ", callback_data="group_sechost_menu")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="block_menu")],
]
sechost_menu = InlineKeyboardMarkup(inline_keyboard=sechost_menu)

group_sechost_menu = [
    [InlineKeyboardButton(text="✍️ Создать/изменить группы СУ", callback_data="add_group_sechost")], [InlineKeyboardButton(text="🗑 Удалить группы СЗИ", callback_data="delete_group_sechost"),
    InlineKeyboardButton(text="📄 Просмотр групп", callback_data="view_group_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="sechost_menu")],
]

group_sechost_menu = InlineKeyboardMarkup(inline_keyboard=
group_sechost_menu)

repeat_add_group_sechost = [
    [InlineKeyboardButton(text="Добавить еще группу СУ", callback_data="add_group_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="group_sechost_menu")]
]
repeat_add_group_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_add_group_sechost)

repeat_view_group_sechost = [
    [InlineKeyboardButton(text="Просмотреть СУ", callback_data="view_group_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="group_sechost_menu")]
]
repeat_view_group_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_view_group_sechost)

repeat_delete_group_sechost = [
    [InlineKeyboardButton(text="Удалить СУ", callback_data="delete_group_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="group_sechost_menu")]
]
repeat_delete_group_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_delete_group_sechost)

repeat_add_sechost = [
    [InlineKeyboardButton(text="Добавить еще СУ", callback_data="add_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="sechost_menu")]
]
repeat_add_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_add_sechost)

repeat_view_sechost = [
    [InlineKeyboardButton(text="Просмотреть СУ", callback_data="view_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="sechost_menu")]
]
repeat_view_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_view_sechost)

repeat_delete_sechost = [
    [InlineKeyboardButton(text="Удалить СУ", callback_data="delete_sechost")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="sechost_menu")]
]
repeat_delete_sechost = InlineKeyboardMarkup(inline_keyboard=repeat_delete_sechost)

rules_menu = [
    [InlineKeyboardButton(text="🚫 Создать/изменить блокировку", callback_data="add_blockrules")],
    [InlineKeyboardButton(text="✍️ Создать/изменить общее правило", callback_data="add_rules")], [InlineKeyboardButton(text="🗑 Удалить правило", callback_data="delete_rules"),
    InlineKeyboardButton(text="📄 Просмотр правил", callback_data="view_rules_menu")],
    [InlineKeyboardButton(text="🔄 Изменить применение правил", callback_data="commit_rules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="block_menu")],
]
rules_menu = InlineKeyboardMarkup(inline_keyboard=rules_menu)

repeat_add_blockrules = [
    [InlineKeyboardButton(text="Добавить еще правила", callback_data="add_blockrules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")]
]
repeat_add_blockrules = InlineKeyboardMarkup(inline_keyboard=repeat_add_blockrules)

repeat_add_rules = [
    [InlineKeyboardButton(text="Добавить еще правила", callback_data="add_rules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")]
]
repeat_add_rules = InlineKeyboardMarkup(inline_keyboard=repeat_add_rules)

repeat_view_rules = [
    [InlineKeyboardButton(text="Просмотреть правила", callback_data="view_rules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")]
]
repeat_view_rules = InlineKeyboardMarkup(inline_keyboard=repeat_view_rules)

repeat_delete_rules = [
    [InlineKeyboardButton(text="Удалить правила", callback_data="delete_rules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")]
]
repeat_delete_rules = InlineKeyboardMarkup(inline_keyboard=repeat_delete_rules)

view_rules_menu = [
    [InlineKeyboardButton(text="🚫 Просмотр блокирующий правил", callback_data="view_blockrules")],
    [InlineKeyboardButton(text="📄 Просмотр общих правил", callback_data="view_rules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")],
]
view_rules_menu = InlineKeyboardMarkup(inline_keyboard=view_rules_menu)

repeat_view_blockrules = [
    [InlineKeyboardButton(text="Посмотреть блокирующие правила", callback_data="view_blockrules")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="view_rules_menu")]
]
repeat_view_blockrules  = InlineKeyboardMarkup(inline_keyboard=repeat_view_blockrules )

check_menu = [
    [InlineKeyboardButton(text="📄 Сводный отчет по адресу", callback_data="summary_menu")],
    [InlineKeyboardButton(text="🔷 VirusTotal", callback_data="virustotal_menu"), InlineKeyboardButton(text="🌐 IPinfo", callback_data="ipinfo_menu")],
    [InlineKeyboardButton(text="⭕️ AbuseIIDB", callback_data="adbuseip_menu"), InlineKeyboardButton(text="🟩 Kaspersky", callback_data="kaspersky_menu")],
    [InlineKeyboardButton(text="🔥 IPQS", callback_data="ipqualityscore_menu"), InlineKeyboardButton(text="👽 Alienvault", callback_data="alienvault_menu")],
    [InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]
]
check_menu = InlineKeyboardMarkup(inline_keyboard=check_menu)

virustotal_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="vt_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="vt_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
virustotal_menu = InlineKeyboardMarkup(inline_keyboard=virustotal_menu)

ipinfo_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="ipi_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="ipi_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
ipinfo_menu = InlineKeyboardMarkup(inline_keyboard=ipinfo_menu)

adbuseip_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="abuseipdb_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="abuseipdb_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
adbuseip_menu = InlineKeyboardMarkup(inline_keyboard=adbuseip_menu)

kaspersky_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="ksp_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="ksp_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
kaspersky_menu = InlineKeyboardMarkup(inline_keyboard=kaspersky_menu)

criminalip_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="cip_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="cip_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
criminalip_menu = InlineKeyboardMarkup(inline_keyboard=criminalip_menu)

alienvault_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="alv_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="alv_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
alienvault_menu = InlineKeyboardMarkup(inline_keyboard=alienvault_menu)

ipqualityscore_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="ipqs_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="ipqs_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
ipqualityscore_menu = InlineKeyboardMarkup(inline_keyboard=ipqualityscore_menu)

summary_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об адресах", callback_data="summary_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с адресами", callback_data="summary_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
summary_menu  = InlineKeyboardMarkup(inline_keyboard=summary_menu )

admin_menu = [
    [InlineKeyboardButton(text="👨‍🔧Пользователи", callback_data="users_menu")],
    [InlineKeyboardButton(text="📄 Отчет об использовании бота", callback_data="report_menu")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="main_menu")],
]
admin_menu = InlineKeyboardMarkup(inline_keyboard=admin_menu)

users_menu = [
    [InlineKeyboardButton(text="👨‍🔧 Добавить администратора", callback_data="add_admin")],
    [InlineKeyboardButton(text="👨‍🔧 Бан пользователя", callback_data="ban_user")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="admin_menu")],
]
users_menu = InlineKeyboardMarkup(inline_keyboard=users_menu)

report_menu = [
    [InlineKeyboardButton(text="👨‍🔧Данные о пользователях", callback_data="report_users")],
    [InlineKeyboardButton(text="📄 История команд", callback_data="report_history")],
    [InlineKeyboardButton(text="🚫 Блокировки", callback_data="report_block"),
     InlineKeyboardButton(text="⚙️ Проверки", callback_data="report_сheck")],
    [InlineKeyboardButton(text="🌐 Сетевые устройства", callback_data="report_sechosts")],
    [InlineKeyboardButton(text="Выгрузка статистики", callback_data="report_download")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="admin_menu")]
]
report_menu = InlineKeyboardMarkup(inline_keyboard=report_menu)

exit_kb = ReplyKeyboardMarkup(keyboard=[[KeyboardButton(text="◀️ Выйти в меню")]], resize_keyboard=True, input_field_placeholder='Выберите пункт меню...')
back_vt = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="virustotal_menu")]])
back_ipinfo = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="ipinfo_menu")]])
back_adbuseip = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="adbuseip_menu")]])
back_kaspersky = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="kaspersky_menu")]])
back_criminalip = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="criminalip_menu")]])
back_alienvault = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="alienvault_menu")]])
back_ipqualityscore = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="ipqualityscore_menu")]])
back_summary = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="summary_menu")]])
back_admin = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="admin_menu")]])
back_users = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="users_menu")]])
back_block = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="block_menu")]])
back_blocklist = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="blocklist_menu")]])
back_sechost = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="sechost_menu")]])
back_group_sechost = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="group_sechost_menu")]])
back_rule = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="rules_menu")]])
back_view_rules_menu = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="view_rules_menu")]])
iexit_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]])
