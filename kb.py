# Bot keyboards

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove

start_menu = [
    [InlineKeyboardButton(text="📄 Проверить IP", callback_data="check_menu")],
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
start_menu = InlineKeyboardMarkup(inline_keyboard=start_menu)

check_menu = [
    [InlineKeyboardButton(text="📄 Сводный отчет по адресу", callback_data="summary_menu")],
    [InlineKeyboardButton(text="🔷 VirusTotal", callback_data="virustotal_menu"), InlineKeyboardButton(text="🌐 IPinfo", callback_data="ipinfo_menu")],
    [InlineKeyboardButton(text="⭕️ AbuseIIDB", callback_data="adbuseip_menu"), InlineKeyboardButton(text="🟩 Kaspersky", callback_data="kaspersky_menu")],
    [InlineKeyboardButton(text="🔥 IPQS", callback_data="ipqualityscore_menu"), InlineKeyboardButton(text="👽 Alienvault", callback_data="alienvault_menu")],
    [InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]
]
check_menu = InlineKeyboardMarkup(inline_keyboard=check_menu)

virustotal_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="vt_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="vt_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
virustotal_menu = InlineKeyboardMarkup(inline_keyboard=virustotal_menu)

ipinfo_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="ipi_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="ipi_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
ipinfo_menu = InlineKeyboardMarkup(inline_keyboard=ipinfo_menu)

adbuseip_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="abuseipdb_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="abuseipdb_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
adbuseip_menu = InlineKeyboardMarkup(inline_keyboard=adbuseip_menu)

kaspersky_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="ksp_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="ksp_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
kaspersky_menu = InlineKeyboardMarkup(inline_keyboard=kaspersky_menu)

criminalip_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="cip_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="cip_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
criminalip_menu = InlineKeyboardMarkup(inline_keyboard=criminalip_menu)

alienvault_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="alv_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="alv_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
alienvault_menu = InlineKeyboardMarkup(inline_keyboard=alienvault_menu)

ipqualityscore_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="ipqs_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="ipqs_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
ipqualityscore_menu = InlineKeyboardMarkup(inline_keyboard=ipqualityscore_menu)

summary_menu = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="summary_ip")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="summary_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check_menu")],
]
summary_menu  = InlineKeyboardMarkup(inline_keyboard=summary_menu )

admin_menu = [
    [InlineKeyboardButton(text="👨‍🔧Пользователи", callback_data="users_menu")],
    [InlineKeyboardButton(text="📄 Отчет об использовании бота", callback_data="report_menu")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="start_menu")],
]
admin_menu = InlineKeyboardMarkup(inline_keyboard=admin_menu)

users_menu = [
    [InlineKeyboardButton(text="👨‍🔧 Добавить администратора", callback_data="add_admin")],
    [InlineKeyboardButton(text="👨‍🔧 Бан пользователя", callback_data="ban_user")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="admin_menu")],
]
users_menu = InlineKeyboardMarkup(inline_keyboard=users_menu)

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
iexit_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]])
