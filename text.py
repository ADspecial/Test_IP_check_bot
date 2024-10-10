greetings = "Привет, {name}, я бот, предназначенный проверки ip адресов"
greetings_group =(
    "Привет, {name}, я бот, предназначенный проверки ip адресов.\n"
    "Для справки введи команду /help"
)
menu = "📍 Главное меню"
check_menu = "📍 Меню проверки адреса"
virustotal_menu = "🔷 Проверка адресов по базам virustotal"
ipinfo_menu = "🌐 Получить информацию об ip из базы ipinfo"
adbuseip_menu = "⭕️ Получить информацию об ip из базы AbuseIPDB"
kaspersky_menu = "🟩 Получить информацию об ip из базы Kaspersky"
criminalip_menu = "🔎 Получить информацию об ip из базы CriminalIP"
alienvault_menu = "👽 Получить информацию об ip из базы Alienvault"
help_group = (
"*Команды бота*\n\n"
"*Общие команды:*\n"
"    - `/start` - запуск бота\n"
"    - `/help` - справка\n\n"
"*Команды проверки по базе Virustotal:*\n"
"    - `/vtcheck {X.X.X.X}` - проверка адресов\n"
"    - `/vtfile` - проверка адресов из txt файла\n\n"
"*Команды проверки по базе IPinfo:*\n"
"    - `/ipicheck {X.X.X.X}` - проверка адресов\n"
"    - `/ipifile` - проверка адресов из txt файла\n\n"
"*Команды проверки по базе AbuseIPDB:*\n"
"    - `/adbcheck {X.X.X.X}` - проверка адресов\n"
"    - `/adbfile` - проверка адресов из txt файла\n\n"
"*Команды проверки по базе Kaspersky:*\n"
"    - `/kspcheck {X.X.X.X}` - проверка адресов\n"
"    - `/kspfile` - проверка адресов из txt файла\n\n"
"*Команды проверки по базе AlienVault:*\n"
"    - `/alvcheck {X.X.X.X}` - проверка адресов\n"
"    - `/alvfile` - проверка адресов из txt файла\n\n"
"*Команды проверки по базе CriminalIP:*\n"
"    - `/cipcheck {X.X.X.X}` - проверка адресов\n"
"    - `/cipfile` - проверка адресов из txt файла\n\n"
"По всем вопросам обращайтесь к @DLekontsev"
)
new_lines = (
    "*Команды меню:*\n"
"    - `/menu` - главное меню\n"
"    - `/check_menu` - меню проверки адреса\n\n"
)
insert_position = help_group.index("    - `/help` - справка\n\n") + len("    - `/help` - справка\n\n")
help_private = help_group[:insert_position] + new_lines + help_group[insert_position:]


about_check_ip = "📝 Введите ip адрес..."
check_ips_list = "📝 Введите ip адреса для проверки..."
send_text_file = "📝 Отправте txt файл с адресами для проверки..."
gen_exit = "Чтобы выйти из диалога с вводом ip адреса нажмите на кнопку"
gen_wait = "⏳Пожалуйста, подождите немного, пока обрабатывает ваш запрос..."
err_ip = "🚫 Произошла ошибка, неверный ip адрес"
