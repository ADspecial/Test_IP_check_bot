# Bot keyboards

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove
start_menu = [
    [InlineKeyboardButton(text="📄 Проверить IP", callback_data="check_menu")],
    [InlineKeyboardButton(text="🔎 Помощь", callback_data="help")]
]
start_menu = InlineKeyboardMarkup(inline_keyboard=start_menu)
check_menu = [
    [InlineKeyboardButton(text="🔤🔤 VirusTotal", callback_data="virustotal_menu"), InlineKeyboardButton(text="🌐 IPinfo", callback_data="ipinfo_menu")],
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
exit_kb = ReplyKeyboardMarkup(keyboard=[[KeyboardButton(text="◀️ Выйти в меню")]], resize_keyboard=True, input_field_placeholder='Выберите пункт меню...')
back_vt = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="virustotal_menu")]])
back_ipinfo = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="ipinfo_menu")]])
iexit_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀️ Выйти в меню", callback_data="view_menu")]])
