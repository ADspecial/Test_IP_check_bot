# Bot keyboards

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove
start_menu = [
    [InlineKeyboardButton(text="📄 Проверить IP", callback_data="check")],
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
start_menu = InlineKeyboardMarkup(inline_keyboard=start_menu)
check_ips = [
    [InlineKeyboardButton(text="🔤🔤 VirusTotal", callback_data="virustotal"), InlineKeyboardButton(text="🌐 IPinfo", callback_data="IPinfo")],
    [InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]
]
check_ips = InlineKeyboardMarkup(inline_keyboard=check_ips)
menu_check_vt = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="about_ip"),InlineKeyboardButton(text="📝 Проверить список IP", callback_data="check_ip_list")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="get_file")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check")],
]
menu_check_vt = InlineKeyboardMarkup(inline_keyboard=menu_check_vt)
menu_check_ipinfo = [
    [InlineKeyboardButton(text="⚙️ Информация об IP", callback_data="about_ip_ipinfo")],
    [InlineKeyboardButton(text="📄 Загрузить файл с IP", callback_data="get_file_ipinfo")],
    [InlineKeyboardButton(text="◀️ Назад", callback_data="check")],
]
menu_check_ipinfo = InlineKeyboardMarkup(inline_keyboard=menu_check_ipinfo)
exit_kb = ReplyKeyboardMarkup(keyboard=[[KeyboardButton(text="◀️ Выйти в меню")]], resize_keyboard=True, input_field_placeholder='Выберите пункт меню...')
back_vt = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="virustotal")]])
back_ipinfo = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="IPinfo")]])
iexit_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]])
